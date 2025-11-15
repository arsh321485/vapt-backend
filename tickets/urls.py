from django.urls import path
from .views import (
    TicketCreateView, TicketListView, TicketOpenListView, TicketClosedListView, TicketDetailView
)

app_name = "tickets"

urlpatterns = [
    path("create/", TicketCreateView.as_view(), name="ticket-create"),
    path("list/", TicketListView.as_view(), name="ticket-list"),
    path("list/open/", TicketOpenListView.as_view(), name="ticket-list-open"),
    path("list/closed/", TicketClosedListView.as_view(), name="ticket-list-closed"),
    path("detail/<str:detail_id>/", TicketDetailView.as_view(), name="ticket-detail"),
]
