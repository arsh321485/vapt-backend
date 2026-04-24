"""
Shared MongoDB connection pool used by all apps.

Import pattern:
    from vaptfix.mongo_client import MongoContext
    from vaptfix.mongo_client import get_shared_client, get_shared_db
"""
import threading
import re
from urllib.parse import urlparse
from typing import Optional

import pymongo
from django.conf import settings
import logging
logger = logging.getLogger(__name__)
_client: Optional[pymongo.MongoClient] = None
_lock = threading.Lock()


def _get_mongo_uri() -> Optional[str]:
    try:
        host = settings.DATABASES["default"]["CLIENT"]["host"]
        if host:
            return host
    except Exception as e:
        logger.warning("Suppressed error: %s", e)
    return getattr(settings, "MONGO_DB_URL", None)


def _get_db_name(uri: str) -> str:
    try:
        path = (urlparse(uri).path or "").lstrip("/")
        if path:
            name = re.split(r"[/?]", path)[0]
            if name:
                return name
    except Exception as e:
        logger.warning("Suppressed error: %s", e)
    return settings.DATABASES.get("default", {}).get("NAME") or "vaptfix"


def get_shared_client() -> pymongo.MongoClient:
    """Return the process-wide shared MongoClient (created once, pooled)."""
    global _client
    if _client is None:
        with _lock:
            if _client is None:
                uri = _get_mongo_uri()
                if not uri:
                    raise RuntimeError(
                        "MongoDB URI not configured. "
                        "Set MONGO_DB_URL or DATABASES['default']['CLIENT']['host']."
                    )
                _client = pymongo.MongoClient(
                    uri,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                    socketTimeoutMS=10000,
                    maxPoolSize=100,
                    minPoolSize=5,
                    retryWrites=True,
                )
    return _client


def get_shared_db(client: Optional[pymongo.MongoClient] = None) -> pymongo.database.Database:
    """Return the default database from the shared client."""
    c = client or get_shared_client()
    uri = _get_mongo_uri() or ""
    return c[_get_db_name(uri)]


class MongoContext:
    """Context manager that yields the shared MongoDB database."""

    def __enter__(self) -> pymongo.database.Database:
        return get_shared_db()

    def __exit__(self, exc_type, exc, tb):
        pass  # Connection is pooled — never close it here
