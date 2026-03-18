from djongo import models
from bson import ObjectId
from django.conf import settings


class ProjectDetail(models.Model):
    INDUSTRY_CHOICES = [
        ('banking_finance', 'Banking & Finance'),
        ('healthcare', 'Healthcare'),
        ('ecommerce', 'E-Commerce'),
        ('government', 'Government'),
        ('telecom', 'Telecom'),
        ('manufacturing', 'Manufacturing'),
        ('education', 'Education'),
        ('other', 'Other'),
    ]

    _id = models.ObjectIdField(primary_key=True, default=ObjectId, editable=False)
    admin = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scoping_project_detail'
    )
    organization_name = models.CharField(max_length=255)
    industry = models.CharField(max_length=50, choices=INDUSTRY_CHOICES)
    country = models.CharField(max_length=100)
    full_name = models.CharField(max_length=255)
    email_address = models.EmailField()
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    is_submitted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'scoping_project_details'

    def __str__(self):
        return f"{self.organization_name} ({self.admin.email})"


class TestingMethodology(models.Model):
    TESTING_TYPE_CHOICES = [
        ('black_box', 'Black Box'),
        ('grey_box', 'Grey Box'),
        ('white_box', 'White Box'),
    ]

    NETWORK_PERSPECTIVE_CHOICES = [
        ('internal', 'Internal'),
        ('external', 'External'),
        ('both', 'Both'),
    ]

    ENVIRONMENT_CHOICES = [
        ('production', 'Production'),
        ('staging', 'Staging'),
        ('dev', 'Dev'),
    ]

    _id = models.ObjectIdField(primary_key=True, default=ObjectId, editable=False)
    admin = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='testing_methodologies'
    )
    testing_type = models.CharField(max_length=20, choices=TESTING_TYPE_CHOICES)
    assessment_categories = models.JSONField(default=list)
    assessment_notes = models.TextField(blank=True, null=True)
    network_perspective = models.CharField(max_length=20, choices=NETWORK_PERSPECTIVE_CHOICES)
    environment = models.CharField(max_length=20, choices=ENVIRONMENT_CHOICES)
    compliance_standards = models.JSONField(default=list)
    compliance_notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'scoping_testing_methodology'
        unique_together = ('admin', 'testing_type')

    def __str__(self):
        return f"{self.testing_type} methodology for {self.admin.email}"
