import logging
from datetime import datetime
from bson import ObjectId

logger = logging.getLogger(__name__)

COLLECTION = "notifications_notification"


def create_notification(admin, recipient_type, notif_type, title, message,
                        metadata=None, recipient_email=''):
    """
    admin  – User instance OR admin_id string (both accepted)
    recipient_email – user's email; '' = broadcast to all users of this admin
    Uses raw pymongo to avoid djongo ORM bugs.
    """
    try:
        from vaptfix.mongo_client import MongoContext
        admin_id = admin if isinstance(admin, str) else str(admin.id)
        print(f"[NOTIF] create_notification: type={notif_type} | recipient={recipient_type} | admin_id={admin_id} | email={recipient_email}", flush=True)
        doc = {
            "_id":             ObjectId(),
            "admin_id":        admin_id,
            "recipient_email": recipient_email or '',
            "recipient_type":  recipient_type,
            "notif_type":      notif_type,
            "title":           title,
            "message":         message,
            "metadata":        metadata or {},
            "is_read":         False,
            "created_at":      datetime.utcnow(),
        }
        with MongoContext() as db:
            db[COLLECTION].insert_one(doc)
    except Exception as exc:
        logger.error("create_notification failed [%s | %s]: %s", notif_type, recipient_type, exc)
