"""
Run this script to manually mark migration 0006_userdetail_platform_fields as applied.
It bypasses djongo's broken auto-increment and inserts directly via pymongo.

Usage:
    python fix_migration.py
"""
import os
import sys
import datetime
from pathlib import Path
from dotenv import load_dotenv
from pymongo import MongoClient

# Load .env from project root
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=True)

MONGO_URI = os.getenv("MONGO_DB_URL") or os.getenv("MONGO_URI")
if not MONGO_URI:
    print("ERROR: MONGO_DB_URL or MONGO_URI not set in .env")
    sys.exit(1)

APP = "users_details"
NAME = "0006_userdetail_platform_fields"

print(f"Connecting to MongoDB...")
client = MongoClient(MONGO_URI)
db = client["vaptfix"]
col = db["django_migrations"]

# Check if already applied
existing = col.find_one({"app": APP, "name": NAME})
if existing:
    print(f"Migration already applied (id={existing.get('id')}). Nothing to do.")
    sys.exit(0)

# Find true max id across ALL documents (avoids __schema__ race condition)
max_doc = col.find_one({}, sort=[("id", -1)])
max_id = max_doc.get("id", 0) if max_doc else 0
new_id = max_id + 1

print(f"Max id in django_migrations: {max_id}")
print(f"Inserting migration record with id={new_id} ...")

result = col.insert_one({
    "id": new_id,
    "app": APP,
    "name": NAME,
    "applied": datetime.datetime.utcnow(),
})

print(f"Success! Inserted _id={result.inserted_id}, id={new_id}")
print(f"Migration '{APP}.{NAME}' is now marked as applied.")

# Verify
check = col.find_one({"app": APP, "name": NAME})
if check:
    print(f"Verified: record exists with id={check.get('id')}")
else:
    print("WARNING: Could not verify insertion!")
