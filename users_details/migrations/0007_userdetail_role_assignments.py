from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users_details', '0006_userdetail_platform_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='userdetail',
            name='role_assignments',
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
