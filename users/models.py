# from djongo import models
# from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
# from django.utils import timezone
# from django.core.validators import EmailValidator
# import uuid

# class UserManager(BaseUserManager):
#     def create_user(self, email, password=None, **extra_fields):
#         if not email:
#             raise ValueError("The Email field must be set")
        
#         email = self.normalize_email(email)
#         extra_fields.setdefault("is_active", True)
        
#         user = self.model(email=email, **extra_fields)
#         user.set_password(password)
#         user.save(using=self._db)
#         return user

#     def create_superuser(self, email, password=None, **extra_fields):
#         extra_fields.setdefault("is_staff", True)
#         extra_fields.setdefault("is_superuser", True)
#         extra_fields.setdefault("is_active", True)
        
#         if extra_fields.get("is_staff") is not True:
#             raise ValueError("Superuser must have is_staff=True.")
#         if extra_fields.get("is_superuser") is not True:
#             raise ValueError("Superuser must have is_superuser=True.")
        
#         return self.create_user(email, password, **extra_fields)


# class User(AbstractBaseUser, PermissionsMixin):
#     # Using UUID as primary key instead of ObjectId
#     id = models.CharField(primary_key=True, default=uuid.uuid4, max_length=36, editable=False)

#     # Personal Information
#     firstname = models.CharField(max_length=100)
#     lastname = models.CharField(max_length=100)
#     email = models.EmailField(
#         unique=True,
#         validators=[EmailValidator()],
#         error_messages={
#             'unique': 'A user with this email already exists.',
#         }
#     )
    
#     # Organization Information
#     organisation_name = models.CharField(max_length=255, blank=True, null=True)
#     organisation_url = models.URLField(blank=True, null=True)
    
#     # Authentication
#     password = models.CharField(max_length=255)
    
#     # Permissions
#     is_active = models.BooleanField(default=True)
#     is_staff = models.BooleanField(default=False)
#     is_superuser = models.BooleanField(default=False)
    
#     # Timestamps
#     created_at = models.DateTimeField(default=timezone.now)
#     updated_at = models.DateTimeField(auto_now=True)
#     last_login = models.DateTimeField(null=True, blank=True)

#     USERNAME_FIELD = "email"
#     REQUIRED_FIELDS = ["firstname", "lastname"]

#     objects = UserManager()

#     class Meta:
#         verbose_name = 'User'
#         verbose_name_plural = 'Users'

#     def __str__(self):
#         return self.email
    
#     @property
#     def full_name(self):
#         return f"{self.firstname} {self.lastname}".strip()
    
#     def get_short_name(self):
#         return self.firstname

#     def save(self, *args, **kwargs):
#         # Ensure UUID is converted to string
#         if self.id and not isinstance(self.id, str):
#             self.id = str(self.id)
#         super().save(*args, **kwargs)



from djongo import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
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
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    # UUID as primary key
    id = models.CharField(
        primary_key=True,
        default=uuid.uuid4,
        max_length=36,
        editable=False
    )

    # Authentication
    email = models.EmailField(
        unique=True,
        validators=[EmailValidator()],
        error_messages={
            'unique': 'A user with this email already exists.',
        }
    )
    password = models.CharField(max_length=255)

    # Permissions
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []  # ✅ no extra required fields

    objects = UserManager()

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        # Ensure UUID stored as string
        if self.id and not isinstance(self.id, str):
            self.id = str(self.id)
        super().save(*args, **kwargs)
