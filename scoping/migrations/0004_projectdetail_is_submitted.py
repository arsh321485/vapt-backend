from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scoping', '0003_fix_mongo_index'),
    ]

    operations = [
        migrations.AddField(
            model_name='projectdetail',
            name='is_submitted',
            field=models.BooleanField(default=False),
        ),
    ]
