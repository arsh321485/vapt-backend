from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users_details', '0004_auto_20260219_1716'),
    ]

    operations = [
        migrations.AddField(
            model_name='userdetail',
            name='slack_channel_ids',
            field=models.JSONField(blank=True, default=list),
        ),
    ]
