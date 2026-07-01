from django.urls import path
from . import views

admin_urlpatterns = [
    path("stats/", views.admin_download_stats, name="admin_automation_stats"),
    path("feedback/", views.admin_all_feedback, name="admin_automation_all_feedback"),
    path("feedback/<int:plugin_id>/", views.admin_script_feedback, name="admin_automation_feedback"),
    path("match/bulk/", views.admin_match_scripts_bulk, name="admin_automation_bulk"),
    path("match/<int:plugin_id>/", views.admin_match_script, name="admin_automation_match"),
    path("", views.admin_list_scripts, name="admin_automation_list"),
]

user_urlpatterns = [
    path("stats/", views.user_download_stats, name="user_automation_stats"),
    path("feedback/", views.user_submit_feedback, name="user_automation_submit_feedback"),
    path("feedback/<int:plugin_id>/", views.user_get_feedback, name="user_automation_get_feedback"),
    path("download/<int:plugin_id>/", views.user_download_script, name="user_automation_download"),
    path("match/bulk/", views.user_match_scripts_bulk, name="user_automation_bulk"),
    path("match/<int:plugin_id>/", views.user_match_script, name="user_automation_match"),
    path("", views.user_list_scripts, name="user_automation_list"),
]
