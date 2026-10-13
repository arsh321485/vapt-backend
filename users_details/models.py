from djongo import models
from bson import ObjectId
from users.models import User
# from location.models import Location

class UserDetail(models.Model):
    _id = models.ObjectIdField(primary_key=True, default=ObjectId, editable=False)

    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name="userdetails_admin")
    # location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name="locations_admin")
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    user_type = models.CharField(max_length=255)
    email = models.EmailField()
    # select_location = models.CharField(max_length=255)
    Member_role = models.JSONField(default=list)
    team_id = models.CharField(max_length=255, blank=True, null=True)
    team_name = models.CharField(max_length=255, blank=True, null=True)
    slack_channel_ids = models.JSONField(default=list, blank=True)
    role_assignments = models.JSONField(default=dict, blank=True)

    # Platform-based login fields
    platform = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        choices=[('email', 'Email'), ('slack', 'Slack'), ('microsoft_teams', 'Microsoft Teams')],
    )
    slack_member_id = models.CharField(max_length=100, blank=True, null=True)
    ms_teams_member_id = models.CharField(max_length=255, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Team"
        verbose_name_plural = "Teams"
        unique_together = [['admin', 'email']]

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"


class CustomTeam(models.Model):
    """
    Real feature request: alongside the 4 fixed teams (Patch Management,
    Configuration Management, Network Security, Architectural Flaws —
    unchanged, still auto-classified/distributed exactly as before), an
    admin can create their OWN team(s), unlimited in number, name typed
    freely by the admin. A custom team has no auto-classification pool of
    its own — ReportAssetsVulnsAPIView treats any role_filter that isn't
    one of the 4 fixed names as "show everything", so the admin picks
    specific assets/vulnerabilities for a member via the same checkbox
    flow already used for the 4 fixed teams, just starting from the full
    set instead of a classified subset.
    """
    _id = models.ObjectIdField(primary_key=True, default=ObjectId, editable=False)

    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name="custom_teams")
    name = models.CharField(max_length=255)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Custom Team"
        verbose_name_plural = "Custom Teams"
        unique_together = [["admin", "name"]]

    def __str__(self):
        return f"{self.name} ({self.admin.email})"
