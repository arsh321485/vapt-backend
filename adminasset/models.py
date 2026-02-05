from django.db import models


class AdminAssetsView(models.Model):
    """
    Placeholder model for Admin Assets tab in Super Admin panel.
    This model doesn't create a database table (managed=False).
    Data is fetched from MongoDB in the admin view.
    """
    admin_email = models.CharField(max_length=255, primary_key=True)

    class Meta:
        managed = False  # No database table
        verbose_name = "Admin Asset"
        verbose_name_plural = "Admin Assets"

    def __str__(self):
        return self.admin_email
