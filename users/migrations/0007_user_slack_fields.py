from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0006_user_login_provider'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='slack_user_id',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='slack_team_id',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]
