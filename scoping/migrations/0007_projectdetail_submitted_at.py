from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scoping', '0006_projectdetail_industry_other'),
    ]

    operations = [
        migrations.AddField(
            model_name='projectdetail',
            name='submitted_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
