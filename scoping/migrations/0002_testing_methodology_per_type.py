import bson.objectid
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import djongo.models.fields


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('scoping', '0001_initial'),
    ]

    operations = [
        # Step 1: Remove old OneToOneField admin
        migrations.RemoveField(
            model_name='testingmethodology',
            name='admin',
        ),
        # Step 2: Remove testing_types JSONField
        migrations.RemoveField(
            model_name='testingmethodology',
            name='testing_types',
        ),
        # Step 3: Add new ForeignKey admin
        migrations.AddField(
            model_name='testingmethodology',
            name='admin',
            field=models.ForeignKey(
                default=None,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='testing_methodologies',
                to=settings.AUTH_USER_MODEL,
            ),
            preserve_default=False,
        ),
        # Step 4: Add testing_type CharField
        migrations.AddField(
            model_name='testingmethodology',
            name='testing_type',
            field=models.CharField(
                choices=[
                    ('black_box', 'Black Box'),
                    ('grey_box', 'Grey Box'),
                    ('white_box', 'White Box'),
                ],
                default='black_box',
                max_length=20,
            ),
            preserve_default=False,
        ),
        # Step 5: Add unique_together constraint
        migrations.AlterUniqueTogether(
            name='testingmethodology',
            unique_together={('admin', 'testing_type')},
        ),
    ]
