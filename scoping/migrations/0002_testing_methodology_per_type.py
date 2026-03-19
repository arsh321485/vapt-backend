from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('scoping', '0001_initial'),
    ]

    operations = [
        # Use SeparateDatabaseAndState to update Django's model state only.
        # Djongo cannot handle DROP COLUMN CASCADE on MongoDB — actual field
        # presence/absence is irrelevant for MongoDB documents, so we skip
        # the DB operations and only update Django's internal state.
        migrations.SeparateDatabaseAndState(
            database_operations=[],
            state_operations=[
                # Step 1: Remove old OneToOneField admin from state
                migrations.RemoveField(
                    model_name='testingmethodology',
                    name='admin',
                ),
                # Step 2: Remove testing_types JSONField from state
                migrations.RemoveField(
                    model_name='testingmethodology',
                    name='testing_types',
                ),
                # Step 3: Add new ForeignKey admin to state
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
                # Step 4: Add testing_type CharField to state
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
                # Step 5: Add unique_together constraint to state
                migrations.AlterUniqueTogether(
                    name='testingmethodology',
                    unique_together={('admin', 'testing_type')},
                ),
            ],
        ),
    ]
