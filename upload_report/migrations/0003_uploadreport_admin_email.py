# Generated manually — real request: the raw upload_reports collection
# only showed admin_id (a UUID), no way to tell which admin a row
# belongs to without a separate lookup. Denormalized alongside `admin`
# the same way nessus_reports already stores both admin_id and
# admin_email.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('upload_report', '0002_auto_20260107_1915'),
    ]

    operations = [
        migrations.AddField(
            model_name='uploadreport',
            name='admin_email',
            field=models.CharField(blank=True, db_index=True, max_length=255, null=True),
        ),
    ]
