from django.urls import path
from .views import TeamsBotMessagesView, TeamsDashboardImageView

app_name = "teams_bot"

urlpatterns = [
    path("bot/messages/", TeamsBotMessagesView.as_view(), name="bot-messages"),
    path("dashboard-image/", TeamsDashboardImageView.as_view(), name="dashboard-image"),
]
