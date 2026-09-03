from djongo import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.core.validators import EmailValidator
import uuid


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")

        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)

        user = self.model(email=email, **extra_fields)
        if password is None:
            user.set_unusable_password()
        else:
            validate_password(password, user)
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    LOGIN_PROVIDER_CHOICES = [
        ('email', 'Email'),
        ('google', 'Google'),
        ('microsoft_teams', 'Microsoft Teams'),
        ('slack', 'Slack'),
        ('jira', 'Jira'),
    ]

    id = models.CharField(
        primary_key=True,
        default=uuid.uuid4,
        max_length=36,
        editable=False
    )

    email = models.EmailField(
        unique=True,
        validators=[EmailValidator()]
    )

    login_provider = models.CharField(
        max_length=50,
        choices=LOGIN_PROVIDER_CHOICES,
        default='email',
        blank=True
    )

    slack_user_id = models.CharField(max_length=50, blank=True, null=True)
    slack_team_id = models.CharField(max_length=50, blank=True, null=True)
    slack_bot_token = models.CharField(max_length=500, blank=True, null=True)

    ms_access_token = models.TextField(blank=True, null=True)
    ms_refresh_token = models.TextField(blank=True, null=True)
    ms_team_id = models.CharField(max_length=255, blank=True, null=True)
    # The admin's own Azure AD object id — distinct from ms_team_id (the
    # TEAM's id). Needed to look up their bot conversation reference for
    # proactive messages (onboarding, notifications), same role slack_user_id
    # plays for Slack.
    ms_teams_object_id = models.CharField(max_length=255, blank=True, null=True)

    jira_access_token = models.TextField(blank=True, null=True)
    jira_refresh_token = models.TextField(blank=True, null=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # Real request: an admin whose report was handed to them via a Super
    # Admin's magic-link invite (see users.invite_utils.claim_invite) gets
    # NO Freemium restrictions at all — automation scripts, asset/vuln
    # count ceilings, everything. Set to True the moment claim_invite
    # successfully reassigns a report to this admin; checked in
    # billing.enforcement._is_unlimited_admin alongside the existing
    # is_superuser/BILLING_UNLIMITED_ADMIN_EMAILS exemptions.
    magic_link_unlimited = models.BooleanField(default=False)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        if self.id and not isinstance(self.id, str):
            self.id = str(self.id)
        super().save(*args, **kwargs)


class SignupOTPSession(models.Model):
    """
    Temporary store for admin signup OTP + password.
    Replaces cache.set/get so it works across all Gunicorn workers.
    Deleted immediately after OTP is verified or if expired (1 minute).
    """
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    password = models.TextField()  # plain-text; hashed when User is created
    created_at = models.DateTimeField(default=timezone.now)
    # Real bug report: a report-claim magic link's invite_token was only
    # ever read from the final Verify-OTP request body — if the frontend
    # only attached it to the earlier Send-OTP call (the one actually made
    # from the invite-link landing page) and didn't re-send it on Verify,
    # the claim silently no-op'd and the invited admin's report never got
    # reassigned. Carrying it here means AdminSignupVerifyOTPView can fall
    # back to whatever was captured at Send-OTP time either way.
    invite_token = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        db_table = 'signup_otp_sessions'

    def __str__(self):
        return f"SignupOTPSession({self.email})"



