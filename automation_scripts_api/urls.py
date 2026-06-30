from django.urls import path
from . import views

urlpatterns = [
    path("match/<int:plugin_id>/", views.match_script, name="automation_script_match"),
    path("match/bulk/", views.match_scripts_bulk, name="automation_script_bulk"),
    path("", views.list_scripts, name="automation_scripts_list"),
]
