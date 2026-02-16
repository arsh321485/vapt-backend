from django.db import models


class SupportRequestView(models.Model):
    """Placeholder model for Support Requests tab in Super Admin panel."""
    admin_email = models.CharField(max_length=255, primary_key=True)

    class Meta:
        managed = False
        verbose_name = "Support Request"
        verbose_name_plural = "Support Requests"

    def __str__(self):
        return self.admin_email


class TicketView(models.Model):
    """Placeholder model for Tickets tab in Super Admin panel."""
    admin_email = models.CharField(max_length=255, primary_key=True)

    class Meta:
        managed = False
        verbose_name = "Ticket"
        verbose_name_plural = "Tickets"

    def __str__(self):
        return self.admin_email


class VulnCardView(models.Model):
    """Placeholder model for Vulnerability Cards tab in Super Admin panel."""
    admin_email = models.CharField(max_length=255, primary_key=True)

    class Meta:
        managed = False
        verbose_name = "Vulnerability Card"
        verbose_name_plural = "Vulnerability Cards"

    def __str__(self):
        return self.admin_email
