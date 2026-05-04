from django.urls import path
from . import views

urlpatterns = [
    # ── Admin endpoints ────────────────────────────────────────────────────────
    path('admin/list/',                              views.AdminNotificationListView.as_view(),         name='admin-notif-list'),
    path('admin/unread-count/',                      views.AdminNotificationUnreadCountView.as_view(),  name='admin-notif-unread'),
    path('admin/mark-all-read/',                     views.AdminMarkAllNotificationsReadView.as_view(), name='admin-notif-mark-all'),
    path('admin/<str:notif_id>/mark-read/',          views.AdminMarkNotificationReadView.as_view(),     name='admin-notif-mark-one'),

    # ── User endpoints ─────────────────────────────────────────────────────────
    path('user/list/',                               views.UserNotificationListView.as_view(),          name='user-notif-list'),
    path('user/unread-count/',                       views.UserNotificationUnreadCountView.as_view(),   name='user-notif-unread'),
    path('user/mark-all-read/',                      views.UserMarkAllNotificationsReadView.as_view(),  name='user-notif-mark-all'),
    path('user/<str:notif_id>/mark-read/',           views.UserMarkNotificationReadView.as_view(),      name='user-notif-mark-one'),
]
