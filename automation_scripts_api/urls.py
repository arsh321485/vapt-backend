from django.urls import path
from . import views

admin_urlpatterns = [
    path("match/bulk/", views.admin_match_scripts_bulk, name="admin_automation_bulk"),
    path("match/<int:plugin_id>/", views.admin_match_script, name="admin_automation_match"),
    path("", views.admin_list_scripts, name="admin_automation_list"),
]

user_urlpatterns = [
    path("match/bulk/", views.user_match_scripts_bulk, name="user_automation_bulk"),
    path("match/<int:plugin_id>/", views.user_match_script, name="user_automation_match"),
    path("", views.user_list_scripts, name="user_automation_list"),
]
