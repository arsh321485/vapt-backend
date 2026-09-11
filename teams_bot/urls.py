from django.urls import path
from .views import (
    TeamsBotMessagesView, TeamsDashboardImageView, TeamsReportDownloadView,
    TeamsScriptDownloadView, TeamsAIScriptDownloadView,
)

app_name = "teams_bot"

urlpatterns = [
    path("bot/messages/", TeamsBotMessagesView.as_view(), name="bot-messages"),
    path("dashboard-image/", TeamsDashboardImageView.as_view(), name="dashboard-image"),
    path("report-download/", TeamsReportDownloadView.as_view(), name="report-download"),
    path("script-download/", TeamsScriptDownloadView.as_view(), name="script-download"),
    path("ai-script-download/", TeamsAIScriptDownloadView.as_view(), name="ai-script-download"),
]
