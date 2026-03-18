from django.db import migrations
from django.conf import settings


def fix_mongo_indexes(apps, schema_editor):
    """
    Drop old unique index on admin_id (from OneToOneField era).
    Create new compound index on (admin_id, testing_type).
    """
    import pymongo

    try:
        mongo_uri = settings.DATABASES['default']['CLIENT']['host']
    except Exception:
        mongo_uri = getattr(settings, 'MONGO_DB_URL', None)

    if not mongo_uri:
        print("[Migration] No MongoDB URI found — skipping index fix.")
        return

    try:
        with pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000) as client:
            try:
                db = client.get_default_database()
            except Exception:
                dbname = settings.DATABASES['default'].get('NAME', 'vaptfix')
                db = client[dbname]

            collection = db['scoping_testing_methodology']

            # List existing indexes
            existing_indexes = collection.index_information()
            print(f"[Migration] Existing indexes: {list(existing_indexes.keys())}")

            # Drop old unique index on admin_id if it exists
            for index_name, index_info in existing_indexes.items():
                key_fields = [k for k, _ in index_info.get('key', [])]
                is_unique = index_info.get('unique', False)
                if key_fields == ['admin_id'] and is_unique:
                    collection.drop_index(index_name)
                    print(f"[Migration] Dropped old unique index: {index_name}")

            # Create compound index on (admin_id, testing_type) — unique
            collection.create_index(
                [('admin_id', pymongo.ASCENDING), ('testing_type', pymongo.ASCENDING)],
                unique=True,
                name='admin_id_testing_type_unique'
            )
            print("[Migration] Created compound unique index on (admin_id, testing_type).")

    except Exception as e:
        print(f"[Migration] Index fix failed: {e}")
        raise


def reverse_fix(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('scoping', '0002_testing_methodology_per_type'),
    ]

    operations = [
        migrations.RunPython(fix_mongo_indexes, reverse_fix),
    ]
