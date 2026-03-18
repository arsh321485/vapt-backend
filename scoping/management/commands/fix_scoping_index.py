import pymongo
from django.core.management.base import BaseCommand
from django.conf import settings


class Command(BaseCommand):
    help = 'Fix MongoDB index on scoping_testing_methodology: drop old unique admin_id index, create compound (admin_id, testing_type) index'

    def handle(self, *args, **options):
        try:
            mongo_uri = settings.DATABASES['default']['CLIENT']['host']
        except Exception:
            mongo_uri = getattr(settings, 'MONGO_DB_URL', None)

        if not mongo_uri:
            self.stderr.write('No MongoDB URI found.')
            return

        with pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000) as client:
            try:
                db = client.get_default_database()
            except Exception:
                dbname = settings.DATABASES['default'].get('NAME', 'vaptfix')
                db = client[dbname]

            collection = db['scoping_testing_methodology']

            # Show current indexes
            existing = collection.index_information()
            self.stdout.write(f'Current indexes: {list(existing.keys())}')

            # Drop ALL unique indexes on admin_id alone
            dropped = []
            for name, info in existing.items():
                keys = [k for k, _ in info.get('key', [])]
                if keys == ['admin_id'] and info.get('unique', False):
                    collection.drop_index(name)
                    dropped.append(name)
                    self.stdout.write(self.style.WARNING(f'Dropped index: {name}'))

            if not dropped:
                self.stdout.write('No old unique admin_id index found — already clean.')

            # Create compound unique index
            collection.create_index(
                [('admin_id', pymongo.ASCENDING), ('testing_type', pymongo.ASCENDING)],
                unique=True,
                name='admin_id_testing_type_unique'
            )
            self.stdout.write(self.style.SUCCESS(
                'Created compound unique index on (admin_id, testing_type).'
            ))

            # Confirm
            final = collection.index_information()
            self.stdout.write(f'Final indexes: {list(final.keys())}')
