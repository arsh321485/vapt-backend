"""
One-time fix: fetch ritikabhikonde.sitl@gmail.com's Slack channel memberships
and save to slack_channel_ids in users_details_userdetail.

Run: python fix_slack_channels.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vaptfix.settings")

import django
django.setup()

from django.conf import settings
import pymongo, requests
from bson import ObjectId
from datetime import datetime, timezone

MONGO_URI = settings.DATABASES['default']['CLIENT']['host']
DB_NAME = settings.DATABASES['default'].get('NAME', 'vaptfix')

USER_UUID = "f41d3dfd-6b66-452d-99f3-9037e7681112"
SLACK_MEMBER_ID = "U0B6L7B3ZB7"
UD_OID = ObjectId("6a18062865b2ed93f9d91b03")

with pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000) as client:
    db = client[DB_NAME]

    # Get bot token from users_user
    user = db['users_user'].find_one({'id': USER_UUID}, {'slack_bot_token': 1, 'email': 1})
    if not user:
        print("[ERROR] User not found")
        sys.exit(1)

    bot_token = user.get('slack_bot_token')
    if not bot_token:
        print("[ERROR] No slack_bot_token found for user")
        sys.exit(1)

    print(f"[OK] Found bot_token for {user['email']}")

    # Try users.conversations (requires channels:read scope — added in latest code deploy)
    resp = requests.get(
        "https://slack.com/api/users.conversations",
        headers={"Authorization": f"Bearer {bot_token}"},
        params={
            "user": SLACK_MEMBER_ID,
            "types": "public_channel,private_channel",
            "limit": 200,
            "exclude_archived": "true",
        },
        timeout=15,
    )
    data = resp.json()

    if not data.get("ok"):
        print(f"[ERROR] Slack API error: {data.get('error')}")
        print("[HINT] The bot token stored in DB was issued WITHOUT channels:read scope.")
        print("[HINT] Admin needs to re-authorize the Slack app to get a new token.")
        print("[HINT] Once re-authorized, run this script again OR just log in via Slack again.")
        sys.exit(1)

    channels = data.get("channels", [])
    channel_ids = [c["id"] for c in channels if c.get("id")]
    channel_names = [c.get("name", c["id"]) for c in channels]
    print(f"[OK] User is member of {len(channel_ids)} channels: {channel_names}")

    print(f"[OK] Found {len(channel_ids)} channels: {channel_names}")

    if channel_ids:
        r = db['users_details_userdetail'].update_one(
            {'_id': UD_OID},
            {'$set': {
                'slack_channel_ids': channel_ids,
                'updated_at': datetime.now(timezone.utc),
            }}
        )
        print(f"[OK] Updated slack_channel_ids: matched={r.matched_count}, modified={r.modified_count}")
    else:
        print("[WARN] No channels found — slack_channel_ids not updated")

    # Verify
    print("\n--- Verification ---")
    ud = db['users_details_userdetail'].find_one(
        {'_id': UD_OID},
        {'email': 1, 'platform': 1, 'slack_member_id': 1, 'slack_channel_ids': 1}
    )
    print(ud)

print("\nDone.")
