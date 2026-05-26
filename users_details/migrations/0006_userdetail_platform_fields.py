from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users_details', '0005_userdetail_slack_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='userdetail',
            name='platform',
            field=models.CharField(
                blank=True,
                null=True,
                max_length=50,
                choices=[('email', 'Email'), ('slack', 'Slack'), ('microsoft_teams', 'Microsoft Teams')],
            ),
        ),
        migrations.AddField(
            model_name='userdetail',
            name='slack_member_id',
            field=models.CharField(blank=True, null=True, max_length=100),
        ),
        migrations.AddField(
            model_name='userdetail',
            name='ms_teams_member_id',
            field=models.CharField(blank=True, null=True, max_length=255),
        ),
    ]
