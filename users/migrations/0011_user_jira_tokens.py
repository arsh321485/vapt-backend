from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0010_signupotpsession'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='jira_access_token',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='jira_refresh_token',
            field=models.TextField(blank=True, null=True),
        ),
    ]
