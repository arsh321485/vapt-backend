"""
Shared MongoDB-backed Django cache backend.

Real bug report: the previous cache backend (FileBasedCache) stores every
entry on local disk under this process's own filesystem — fine as long as
every reader/writer of the cache runs on the SAME machine, but this app's
data-fix management commands (dedupe_vulnerabilities_by_host,
unlock_freemium_hosts_for_admin's cache-invalidation step, ...) are
sometimes run from a different machine (a dev box) than the one actually
serving live traffic (the production server's gunicorn workers). A
cache.delete()/cache.clear() issued from the "wrong" machine silently did
nothing to the live site's own cache — confirmed real: a management
command's fix landed correctly in MongoDB (the shared source of truth)
but the admin dashboard kept showing pre-fix numbers for up to the 5-minute
TTL, because the command's own cache invalidation cleared a DIFFERENT,
local `django_cache/` directory that the production server never reads.

Backing the cache by the SAME shared MongoDB connection every environment
already talks to (vaptfix.mongo_client) makes cache.get/set/delete/clear
consistent no matter which machine issues them — a fix run from anywhere
immediately invalidates what every gunicorn worker on every machine sees.
"""
import pickle
from datetime import datetime

import pymongo
from bson import Binary
from django.core.cache.backends.base import BaseCache, DEFAULT_TIMEOUT

from vaptfix.mongo_client import get_shared_client, get_shared_db

DEFAULT_COLLECTION = "app_cache"

# pymongo hands back BSON dates as naive UTC datetimes by default (no
# tz_aware=True on this app's shared client — same convention every other
# raw-pymongo read in this codebase already follows, e.g. asset_service.py's
# resolve_management_testing_asset_count stripping tzinfo before comparing).
# Store naive UTC here too so writes and reads compare directly.
def _utcnow():
    return datetime.utcnow()

# TTL index only fires on real Date values, so "never expires" (timeout=None)
# is stored as a fixed far-future date instead of NULL — this also sidesteps
# BSON's null-sorts-before-every-date comparison quirk, which would
# otherwise make a $lte-now check on a NULL expires_at incorrectly match.
_NEVER_EXPIRES = datetime(9999, 1, 1)

_indexes_ensured = set()


class MongoCache(BaseCache):
    def __init__(self, location, params):
        super().__init__(params)
        options = params.get("OPTIONS") or {}
        self._collection_name = options.get("COLLECTION", DEFAULT_COLLECTION)

    def _collection(self):
        coll = get_shared_db(get_shared_client())[self._collection_name]
        if self._collection_name not in _indexes_ensured:
            try:
                coll.create_index("expires_at", expireAfterSeconds=0)
            except Exception:
                pass
            _indexes_ensured.add(self._collection_name)
        return coll

    def _expiry(self, timeout):
        # BaseCache.get_backend_timeout returns an ABSOLUTE epoch timestamp
        # (time.time() + timeout), not a duration — treating it as a delta
        # to add to "now" (an earlier version of this did) put every
        # expiry decades in the future, so nothing ever actually expired.
        epoch_seconds = self.get_backend_timeout(timeout)
        if epoch_seconds is None:
            return _NEVER_EXPIRES
        return datetime.utcfromtimestamp(epoch_seconds)

    @staticmethod
    def _pack(value):
        return Binary(pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL))

    @staticmethod
    def _unpack(raw):
        return pickle.loads(bytes(raw))

    def add(self, key, value, timeout=DEFAULT_TIMEOUT, version=None):
        k = self.make_key(key, version=version)
        self.validate_key(k)
        now = _utcnow()
        expires_at = self._expiry(timeout)
        try:
            # Matches only a MISSING doc (upsert inserts) or an EXPIRED one
            # (upsert overwrites it) — a still-valid existing entry matches
            # neither, so the upsert tries to insert a duplicate _id and
            # raises instead, which add() reports as "already set".
            self._collection().update_one(
                {"_id": k, "expires_at": {"$lte": now}},
                {"$set": {"value": self._pack(value), "expires_at": expires_at}},
                upsert=True,
            )
            return True
        except pymongo.errors.DuplicateKeyError:
            return False

    def get(self, key, default=None, version=None):
        k = self.make_key(key, version=version)
        self.validate_key(k)
        doc = self._collection().find_one({"_id": k})
        if not doc:
            return default
        expires_at = doc.get("expires_at")
        if expires_at is not None and expires_at <= _utcnow():
            return default
        try:
            return self._unpack(doc["value"])
        except Exception:
            return default

    def set(self, key, value, timeout=DEFAULT_TIMEOUT, version=None):
        k = self.make_key(key, version=version)
        self.validate_key(k)
        expires_at = self._expiry(timeout)
        self._collection().update_one(
            {"_id": k},
            {"$set": {"value": self._pack(value), "expires_at": expires_at}},
            upsert=True,
        )

    def touch(self, key, timeout=DEFAULT_TIMEOUT, version=None):
        k = self.make_key(key, version=version)
        self.validate_key(k)
        expires_at = self._expiry(timeout)
        res = self._collection().update_one({"_id": k}, {"$set": {"expires_at": expires_at}})
        return res.matched_count > 0

    def delete(self, key, version=None):
        k = self.make_key(key, version=version)
        self.validate_key(k)
        res = self._collection().delete_one({"_id": k})
        return res.deleted_count > 0

    def has_key(self, key, version=None):
        k = self.make_key(key, version=version)
        doc = self._collection().find_one({"_id": k}, {"expires_at": 1})
        if not doc:
            return False
        expires_at = doc.get("expires_at")
        return not (expires_at is not None and expires_at <= _utcnow())

    def clear(self):
        self._collection().delete_many({})

    def incr(self, key, delta=1, version=None):
        k = self.make_key(key, version=version)
        self.validate_key(k)
        doc = self._collection().find_one({"_id": k})
        now = _utcnow()
        if not doc or (doc.get("expires_at") is not None and doc["expires_at"] <= now):
            raise ValueError("Key '%s' not found" % key)
        new_value = self._unpack(doc["value"]) + delta
        self._collection().update_one({"_id": k}, {"$set": {"value": self._pack(new_value)}})
        return new_value
