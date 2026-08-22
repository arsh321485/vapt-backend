from django.urls import path
from .views import TeamsBotMessagesView

app_name = "teams_bot"

urlpatterns = [
    path("bot/messages/", TeamsBotMessagesView.as_view(), name="bot-messages"),
]
