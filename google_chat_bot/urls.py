from django.urls import path
from .views import GoogleChatBotMessagesView

app_name = "google_chat_bot"

urlpatterns = [
    path("bot/messages/", GoogleChatBotMessagesView.as_view(), name="bot-messages"),
]
