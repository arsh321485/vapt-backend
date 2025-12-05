# utilities: get mongo uri, db, parse floats, context manager
import re
from typing import Optional, Any
from django.conf import settings
import pymongo

def get_mongo_uri() -> Optional[str]:
    try:
        client_cfg = settings.DATABASES['default'].get('CLIENT')
        if isinstance(client_cfg, dict):
            host = client_cfg.get('host')
            if host:
                return host
        elif client_cfg:
            return client_cfg
    except Exception:
        pass
    return getattr(settings, "MONGO_DB_URL", None)

def get_mongo_db(client: pymongo.MongoClient):
    try:
        db = client.get_default_database()
        if db:
            return db
    except Exception:
        pass
    try:
        name = settings.DATABASES['default'].get('NAME')
        if name:
            return client[name]
    except Exception:
        pass
    return client.get_database("vaptfix")

def safe_float_from(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        s = str(value)
        m = re.search(r"(-?\d+(\.\d+)?)", s)
        if m:
            try:
                return float(m.group(1))
            except Exception:
                return None
    return None
def parse_timeline_to_hours(timeline: str) -> int:
    """
    Convert timeline strings like:
      "1 Day", "2 Days", "1 Week", "2 Weeks", "10 Days"
    to integer hours. If unknown, return 0.
    """
    if not timeline:
        return 0
    s = str(timeline).strip().lower()
    # direct hours like "3 hrs", "2 hours"
    m_hours = re.search(r'(\d+)\s*(h|hr|hrs|hour|hours)\b', s)
    if m_hours:
        return int(m_hours.group(1))
    # days
    m_day = re.search(r'(\d+)\s*(d|day|days)\b', s)
    if m_day:
        days = int(m_day.group(1))
        return days * 24
    # weeks
    m_week = re.search(r'(\d+)\s*(w|week|weeks)\b', s)
    if m_week:
        weeks = int(m_week.group(1))
        return weeks * 7 * 24
    # fallback to number-only interpret as days
    m_num = re.search(r'^\s*(\d+)\s*$', s)
    if m_num:
        return int(m_num.group(1)) * 24
    return 0

def humanize_hours(hours: float) -> str:
    """
    Convert hours (float/int) to 'Xd Y hrs' or 'Y hrs' string.
    Examples:
      168 -> '7d 0 hrs' or simplified '7d'
      59  -> '2d 11 hrs'
    """
    if hours is None:
        return ""
    try:
        h = int(round(hours))
    except Exception:
        return ""
    days = h // 24
    rem = h % 24
    if days > 0:
        if rem:
            return f"{days}d {rem} hrs"
        return f"{days}d"
    return f"{rem} hrs" if rem else "0 hrs"

class MongoContext:
    """Context manager for short-lived MongoDB client"""
    def __init__(self):
        self.uri = get_mongo_uri()
        self.client = None
    def __enter__(self):
        if not self.uri:
            raise RuntimeError("MongoDB URI not configured. Set MONGO_DB_URL or DATABASES['default']['CLIENT']['host'].")
        self.client = pymongo.MongoClient(self.uri, serverSelectionTimeoutMS=5000)
        return get_mongo_db(self.client)
    def __exit__(self, exc_type, exc, tb):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
