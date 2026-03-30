from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0011_user_jira_tokens'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='ms_team_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
