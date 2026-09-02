import datetime as _dt

from bson import ObjectId
from django.core.cache import cache
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions

from vaptfix.mongo_client import MongoContext
from .deadline_checker import check_deadlines_for_admin

COLLECTION = "notifications_notification"

# Real perf report: NotificationPanel.vue polls unread-count (and
# sometimes the full list) every 10s, from possibly more than one mounted
# instance at once — real, avoidable Mongo load on every single poll tick
# regardless of whether anything actually changed. A short cache (well
# under the poll interval, so a genuinely new notification still shows up
# within one poll cycle) absorbs duplicate/overlapping polls without
# making the badge feel stale. Explicitly busted below wherever a
# notification is created or marked read, so it's still correct beyond
# just "eventually" within the TTL.
_NOTIF_CACHE_TTL = 8


def _bust_admin_cache(admin_id):
    cache.delete(f"notif_admin_unread_{admin_id}")
    cache.delete(f"notif_admin_list_{admin_id}")


def _bust_user_cache(admin_id, user_email):
    cache.delete(f"notif_user_unread_{admin_id}_{user_email}")
    cache.delete(f"notif_user_list_{admin_id}_{user_email}")


def _serialize(doc):
    created = doc.get("created_at")
    # notifications/utils.py's create_notification() stores this with plain
    # datetime.utcnow() — genuinely UTC but naive. Attach UTC explicitly so
    # the serialized string carries an offset a browser's `new Date(...)`
    # can't misread as its own local time.
    if isinstance(created, _dt.datetime) and created.tzinfo is None:
        created = created.replace(tzinfo=_dt.timezone.utc)
    return {
        "id":              str(doc.get("_id", "")),
        "notif_type":      doc.get("notif_type", ""),
        "title":           doc.get("title", ""),
        "message":         doc.get("message", ""),
        "metadata":        doc.get("metadata") or {},
        "is_read":         doc.get("is_read", False),
        "recipient_type":  doc.get("recipient_type", ""),
        "recipient_email": doc.get("recipient_email", ""),
        "created_at":      created.isoformat() if created else None,
    }


def _get_admin_id_for_user(user_email):
    from django.core.cache import cache
    cache_key = f"notif_admin_id_{user_email}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached
    try:
        from users_details.models import UserDetail
        detail = UserDetail.objects.filter(email=user_email).first()
        if detail:
            admin_id = str(detail.admin_id)
            cache.set(cache_key, admin_id, 300)
            return admin_id
    except Exception:
        pass
    return None


# ─── Admin Views ──────────────────────────────────────────────────────────────

class AdminNotificationListView(APIView):
    """GET /api/notifications/admin/list/"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        admin_id = str(request.user.id)
        cache_key = f"notif_admin_list_{admin_id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached, status=status.HTTP_200_OK)
        check_deadlines_for_admin(admin_id)
        with MongoContext() as db:
            docs = list(db[COLLECTION].find(
                {"admin_id": admin_id, "recipient_type": "admin", "is_read": False},
                sort=[("created_at", -1)]
            ))
        data = [_serialize(d) for d in docs]
        payload = {"count": len(data), "notifications": data}
        cache.set(cache_key, payload, _NOTIF_CACHE_TTL)
        return Response(payload, status=status.HTTP_200_OK)


class AdminNotificationUnreadCountView(APIView):
    """GET /api/notifications/admin/unread-count/"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        admin_id = str(request.user.id)
        cache_key = f"notif_admin_unread_{admin_id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response({"unread_count": cached}, status=status.HTTP_200_OK)
        with MongoContext() as db:
            count = db[COLLECTION].count_documents(
                {"admin_id": admin_id, "recipient_type": "admin", "is_read": False}
            )
        cache.set(cache_key, count, _NOTIF_CACHE_TTL)
        return Response({"unread_count": count}, status=status.HTTP_200_OK)


class AdminMarkNotificationReadView(APIView):
    """
    PATCH /api/notifications/admin/<notif_id>/mark-read/
    Marking as read now permanently removes the notification — once seen,
    it's gone for good (no read-history is kept).
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, notif_id):
        try:
            obj_id = ObjectId(notif_id)
        except Exception:
            return Response({"detail": "Invalid notification ID"}, status=status.HTTP_400_BAD_REQUEST)

        admin_id = str(request.user.id)
        with MongoContext() as db:
            result = db[COLLECTION].delete_one(
                {"_id": obj_id, "admin_id": admin_id, "recipient_type": "admin"}
            )
        if result.deleted_count == 0:
            return Response({"detail": "Notification not found"}, status=status.HTTP_404_NOT_FOUND)
        _bust_admin_cache(admin_id)
        return Response({"detail": "Notification cleared", "id": notif_id}, status=status.HTTP_200_OK)


class AdminMarkAllNotificationsReadView(APIView):
    """
    PATCH /api/notifications/admin/mark-all-read/
    Marking as read now permanently removes the notifications — once seen,
    they're gone for good (no read-history is kept).
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request):
        admin_id = str(request.user.id)
        with MongoContext() as db:
            result = db[COLLECTION].delete_many(
                {"admin_id": admin_id, "recipient_type": "admin", "is_read": False}
            )
        _bust_admin_cache(admin_id)
        return Response(
            {"detail": "All notifications cleared", "deleted": result.deleted_count},
            status=status.HTTP_200_OK
        )


# ─── User Views ───────────────────────────────────────────────────────────────

class UserNotificationListView(APIView):
    """GET /api/notifications/user/list/"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user_email = request.user.email
        admin_id   = _get_admin_id_for_user(user_email)
        if not admin_id:
            return Response({"count": 0, "notifications": []}, status=status.HTTP_200_OK)

        cache_key = f"notif_user_list_{admin_id}_{user_email}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached, status=status.HTTP_200_OK)

        with MongoContext() as db:
            docs = list(db[COLLECTION].find(
                {
                    "admin_id": admin_id,
                    "recipient_type": "user",
                    "recipient_email": {"$in": [user_email, ""]},
                    "is_read": False,
                },
                sort=[("created_at", -1)]
            ))
        data = [_serialize(d) for d in docs]
        payload = {"count": len(data), "notifications": data}
        cache.set(cache_key, payload, _NOTIF_CACHE_TTL)
        return Response(payload, status=status.HTTP_200_OK)


class UserNotificationUnreadCountView(APIView):
    """GET /api/notifications/user/unread-count/"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user_email = request.user.email
        admin_id   = _get_admin_id_for_user(user_email)
        if not admin_id:
            return Response({"unread_count": 0}, status=status.HTTP_200_OK)

        cache_key = f"notif_user_unread_{admin_id}_{user_email}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response({"unread_count": cached}, status=status.HTTP_200_OK)

        with MongoContext() as db:
            count = db[COLLECTION].count_documents({
                "admin_id": admin_id,
                "recipient_type": "user",
                "recipient_email": {"$in": [user_email, ""]},
                "is_read": False,
            })
        cache.set(cache_key, count, _NOTIF_CACHE_TTL)
        return Response({"unread_count": count}, status=status.HTTP_200_OK)


class UserMarkNotificationReadView(APIView):
    """
    PATCH /api/notifications/user/<notif_id>/mark-read/
    Marking as read now permanently removes the notification — once seen,
    it's gone for good (no read-history is kept).
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, notif_id):
        try:
            obj_id = ObjectId(notif_id)
        except Exception:
            return Response({"detail": "Invalid notification ID"}, status=status.HTTP_400_BAD_REQUEST)

        user_email = request.user.email
        admin_id   = _get_admin_id_for_user(user_email)
        if not admin_id:
            return Response({"detail": "User not linked to any admin"}, status=status.HTTP_403_FORBIDDEN)

        with MongoContext() as db:
            result = db[COLLECTION].delete_one(
                {
                    "_id": obj_id,
                    "admin_id": admin_id,
                    "recipient_type": "user",
                    "recipient_email": {"$in": [user_email, ""]},
                }
            )
        if result.deleted_count == 0:
            return Response({"detail": "Notification not found"}, status=status.HTTP_404_NOT_FOUND)
        _bust_user_cache(admin_id, user_email)
        return Response({"detail": "Notification cleared", "id": notif_id}, status=status.HTTP_200_OK)


class UserMarkAllNotificationsReadView(APIView):
    """
    PATCH /api/notifications/user/mark-all-read/
    Marking as read now permanently removes the notifications — once seen,
    they're gone for good (no read-history is kept).
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request):
        user_email = request.user.email
        admin_id   = _get_admin_id_for_user(user_email)
        if not admin_id:
            return Response({"detail": "User not linked to any admin"}, status=status.HTTP_403_FORBIDDEN)

        with MongoContext() as db:
            result = db[COLLECTION].delete_many(
                {
                    "admin_id": admin_id,
                    "recipient_type": "user",
                    "recipient_email": {"$in": [user_email, ""]},
                    "is_read": False,
                }
            )
        _bust_user_cache(admin_id, user_email)
        return Response(
            {"detail": "All notifications cleared", "deleted": result.deleted_count},
            status=status.HTTP_200_OK
        )
