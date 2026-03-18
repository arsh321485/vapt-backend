from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0008_auto_20260318_1245'),
    ]

    operations = [
        migrations.DeleteModel(
            name='AdminProjectDetail',
        ),
    ]
