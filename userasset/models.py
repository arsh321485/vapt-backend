from django.db import models


class UserAssetView(models.Model):
    """
    Placeholder model for User Asset tab.
    Data is fetched from MongoDB – no DB table created.
    """
    user_email = models.CharField(max_length=255, primary_key=True)

    class Meta:
        managed = False
        verbose_name = "User Asset"
        verbose_name_plural = "User Assets"

    def __str__(self):
        return self.user_email
