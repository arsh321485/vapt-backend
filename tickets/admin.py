# tickets/admin.py
from django.contrib import admin
from .models import Ticket

@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ("subject", "admin", "asset", "category", "status", "created_at", "updated_at")
    search_fields = ("subject", "asset", "category", "description", "admin__email")
    list_filter = ("status", "category", "created_at")
    readonly_fields = ("_id", "created_at", "updated_at")
