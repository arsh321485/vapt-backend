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
_indexes_ensured = False
_indexes_lock = threading.Lock()


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
                    serverSelectionTimeoutMS=30000,
                    connectTimeoutMS=20000,
                    socketTimeoutMS=45000,
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


def ensure_performance_indexes(db) -> None:
    """
    Ensure frequently-used read path indexes exist.
    Safe to call repeatedly; actual index creation runs once per process.
    """
    global _indexes_ensured
    if _indexes_ensured:
        return
    with _indexes_lock:
        if _indexes_ensured:
            return
        try:
            db["nessus_reports"].create_index([("admin_id", 1), ("uploaded_at", -1)], name="idx_nessus_admin_uploaded")
            db["nessus_reports"].create_index([("admin_email", 1), ("uploaded_at", -1)], name="idx_nessus_email_uploaded")

            db["vulnerability_cards"].create_index([("report_id", 1)], name="idx_cards_report")
            db["vulnerability_cards"].create_index(
                [("report_id", 1), ("vulnerability_name", 1), ("host_name", 1)],
                name="idx_cards_report_vuln_host",
            )

            db["fix_vulnerabilities"].create_index([("report_id", 1), ("created_by", 1)], name="idx_fix_report_createdby")
            db["fix_vulnerabilities"].create_index([("report_id", 1), ("admin_id", 1)], name="idx_fix_report_admin")

            db["fix_vulnerabilities_closed"].create_index(
                [("report_id", 1), ("created_by", 1)],
                name="idx_fix_closed_report_createdby",
            )
            db["fix_vulnerabilities_closed"].create_index(
                [("report_id", 1), ("admin_id", 1)],
                name="idx_fix_closed_report_admin",
            )
            db["fix_vulnerability_steps"].create_index(
                [("fix_vulnerability_id", 1), ("status", 1)],
                name="idx_fix_steps_fixid_status",
            )
        except Exception as e:
            # Keep request path resilient even if index creation is blocked.
            logger.warning("Index ensure skipped due to error: %s", e)
        finally:
            _indexes_ensured = True
