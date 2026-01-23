"""
Script to fix MongoDB index conflicts before running migrations.
Run this if migration fails due to existing index.
"""
import pymongo
from django.conf import settings
import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vaptfix.settings')
django.setup()

# Get MongoDB connection
try:
    mongo_uri = settings.DATABASES['default']['CLIENT']['host']
    db_name = settings.DATABASES['default'].get('NAME', 'vaptfix')
    
    client = pymongo.MongoClient(mongo_uri)
    db = client[db_name]
    collection = db['scope']
    
    # List all indexes
    print("Current indexes on 'scope' collection:")
    for index in collection.list_indexes():
        print(f"  - {index['name']}: {index.get('key', {})}")
    
    # Drop the conflicting index if it exists
    try:
        collection.drop_index('scope_file_up_ee99ab_idx')
        print("\n✅ Dropped index: scope_file_up_ee99ab_idx")
    except Exception as e:
        print(f"\n⚠️  Could not drop index (may not exist): {e}")
    
    print("\n✅ Ready to run migrations. Run: python manage.py migrate")
    
except Exception as e:
    print(f"❌ Error: {e}")
    print("\nYou can also manually drop the index using MongoDB shell:")
    print("  db.scope.dropIndex('scope_file_up_ee99ab_idx')")
