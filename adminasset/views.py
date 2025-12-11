# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status, permissions
# from django.conf import settings
# from django.utils.timezone import is_naive, make_aware
# from datetime import datetime
# import pymongo
# from urllib.parse import urlparse
# import re

# from .serializers import AdminAssetSerializer

# NESSUS_COLLECTION = "nessus_reports"


# # ---------------- Mongo Context ---------------- #
# class MongoContext:
#     def __init__(self):
#         self.uri = getattr(settings, "MONGO_DB_URL", None) or settings.DATABASES.get('default', {}).get('CLIENT', {}).get('host')
#         self.client = None
#         self.db = None

#     def __enter__(self):
#         if not self.uri:
#             raise RuntimeError("MongoDB URI not configured")
#         self.client = pymongo.MongoClient(self.uri, serverSelectionTimeoutMS=5000)

#         # Pick DB name
#         dbname = getattr(settings, "MONGO_DB_NAME", None)
#         if not dbname:
#             parsed = urlparse(self.uri)
#             path = (parsed.path or "").lstrip("/")
#             if path:
#                 dbname = re.split(r"[/?]", path)[0]

#         if not dbname:
#             try:
#                 db_default = self.client.get_default_database()
#                 if db_default:
#                     dbname = db_default.name
#             except:
#                 pass

#         if not dbname:
#             dbname = "vaptfix"

#         self.db = self.client[dbname]
#         return self.db

#     def __exit__(self, exc_type, exc, tb):
#         if self.client:
#             self.client.close()


# # ---------------- Helper ---------------- #
# def _iso(dt):
#     if not dt:
#         return None
#     if isinstance(dt, datetime):
#         if is_naive(dt):
#             dt = make_aware(dt)
#         return dt.isoformat()
#     return str(dt)


# # ---------------- Main View ---------------- #
# class ReportAssetsAPIView(APIView):
#     """
#     Fetch assets FROM ONE SPECIFIC REPORT.
#     GET /api/adminasset/report/<report_id>/assets/
#     """
#     permission_classes = [permissions.IsAuthenticated]

#     def get(self, request, report_id):
#         try:
#             with MongoContext() as db:
#                 coll = db[NESSUS_COLLECTION]

#                 # Fetch ONE report
#                 doc = coll.find_one({"report_id": str(report_id)})
#                 if not doc:
#                     return Response({"detail": "report not found"}, status=404)

#                 member_type = doc.get("member_type") or ""
#                 admin_email = doc.get("admin_email") or ""
#                 uploaded_at = doc.get("uploaded_at")

#                 # Organisation name
#                 scan_info = doc.get("scan_info") or {}
#                 organisation_name = ""
#                 if isinstance(scan_info, dict):
#                     organisation_name = (
#                         scan_info.get("organisation_name")
#                         or scan_info.get("organization")
#                         or scan_info.get("organisation")
#                         or ""
#                     )

#                 # Aggregate assets inside this ONE report
#                 assets = {}

#                 for host in doc.get("vulnerabilities_by_host", []) or []:
#                     host_name = host.get("host_name") or host.get("host") or ""
#                     if not host_name:
#                         continue

#                     if host_name not in assets:
#                         assets[host_name] = {
#                             "asset": host_name,
#                             "owner": organisation_name or admin_email,
#                             "exposure": member_type,
#                             "first_seen": uploaded_at,
#                             "last_seen": uploaded_at,
#                             "total_vulnerabilities": 0,
#                             "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
#                             "host_information": host.get("host_information") or {}
#                         }

#                     entry = assets[host_name]

#                     # Count vulns
#                     for v in (host.get("vulnerabilities") or []):
#                         entry["total_vulnerabilities"] += 1
#                         risk = (v.get("risk_factor") or v.get("severity") or "").lower()

#                         if risk.startswith("crit"):
#                             entry["severity_counts"]["critical"] += 1
#                         elif risk.startswith("high"):
#                             entry["severity_counts"]["high"] += 1
#                         elif risk.startswith("med"):
#                             entry["severity_counts"]["medium"] += 1
#                         elif risk.startswith("low"):
#                             entry["severity_counts"]["low"] += 1

#                 # Prepare output
#                 result = []
#                 for ent in assets.values():
#                     result.append({
#                         "asset": ent["asset"],
#                         "owner": ent["owner"],
#                         "exposure": ent["exposure"],
#                         "first_seen": _iso(ent["first_seen"]),
#                         "last_seen": _iso(ent["last_seen"]),
#                         "total_vulnerabilities": ent["total_vulnerabilities"],
#                         "severity_counts": ent["severity_counts"],
#                         "host_information": ent["host_information"],
#                     })

#                 serializer = AdminAssetSerializer(result, many=True)
#                 return Response({"report_id": report_id, "count": len(result), "assets": serializer.data}, status=200)

#         except Exception as exc:
#             import traceback; traceback.print_exc()
#             return Response({"detail": str(exc)}, status=500)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.conf import settings
from urllib.parse import urlparse
from datetime import datetime
from django.utils.timezone import is_naive, make_aware
import pymongo
import re

from .serializers import AdminAssetSerializer

# Import User for organisation_name lookup
try:
    from users.models import User
except Exception:
    User = None

NESSUS_COLLECTION = "nessus_reports"


# ---------------------- Mongo Context ----------------------
class MongoContext:
    def __init__(self):
        self.uri = getattr(settings, "MONGO_DB_URL", None)
        if not self.uri:
            self.uri = settings.DATABASES.get("default", {}).get("CLIENT", {}).get("host")
        self.client = None

    def __enter__(self):
        if not self.uri:
            raise RuntimeError("MongoDB URI not configured.")

        self.client = pymongo.MongoClient(self.uri, serverSelectionTimeoutMS=5000)

        parsed = urlparse(self.uri)
        dbname = parsed.path.replace("/", "") or "vaptfix"

        return self.client[dbname]

    def __exit__(self, exc_type, exc, tb):
        if self.client:
            self.client.close()


# ---------------------- Helper ----------------------
def _iso(v):
    if not v:
        return None
    if isinstance(v, datetime):
        if is_naive(v):
            v = make_aware(v)
        return v.isoformat()
    return str(v)


# ---------------------- MAIN API ----------------------
class ReportAssetsAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]
                doc = coll.find_one({"report_id": str(report_id)})

                if not doc:
                    return Response({"detail": "report not found"}, status=404)

                member_type = doc.get("member_type") or ""
                admin_email = doc.get("admin_email") or ""
                uploaded_at = doc.get("uploaded_at")

                # ---------- ORGANISATION NAME LOGIC ----------
                scan_info = doc.get("scan_info") or {}

                organisation_name = (
                    scan_info.get("organisation_name")
                    or scan_info.get("organization")
                    or scan_info.get("organisation")
                    or ""
                )

                # If not found → try from Django User table
                if not organisation_name and User is not None and admin_email:
                    user = User.objects.filter(email=admin_email).first()
                    if user:
                        organisation_name = getattr(user, "organisation_name", "") or ""

                # Final fallback → NULL (never email!)
                owner_value = organisation_name or ""

                # ---------- ASSET AGGREGATION ----------
                assets = {}

                for host in doc.get("vulnerabilities_by_host", []):
                    host_name = host.get("host_name") or ""
                    if not host_name:
                        continue

                    if host_name not in assets:
                        assets[host_name] = {
                            "asset": host_name,
                            "owner": owner_value,
                            "exposure": member_type,
                            "first_seen": uploaded_at,
                            "last_seen": uploaded_at,
                            "total_vulnerabilities": 0,
                            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                            "host_information": host.get("host_information") or {}
                        }

                    entry = assets[host_name]

                    # Count vulnerabilities
                    for v in host.get("vulnerabilities", []):
                        entry["total_vulnerabilities"] += 1

                        risk = (v.get("risk_factor") or v.get("severity") or "").lower()
                        if risk.startswith("crit"):
                            entry["severity_counts"]["critical"] += 1
                        elif risk.startswith("high"):
                            entry["severity_counts"]["high"] += 1
                        elif risk.startswith("med"):
                            entry["severity_counts"]["medium"] += 1
                        elif risk.startswith("low"):
                            entry["severity_counts"]["low"] += 1

                # ---------- FINAL OUTPUT ----------
                final = []
                for a in assets.values():
                    final.append({
                        "asset": a["asset"],
                        "owner": a["owner"],
                        "exposure": a["exposure"],
                        "first_seen": _iso(a["first_seen"]),
                        "last_seen": _iso(a["last_seen"]),
                        "total_vulnerabilities": a["total_vulnerabilities"],
                        "severity_counts": a["severity_counts"],
                        "host_information": a["host_information"],
                    })

                serializer = AdminAssetSerializer(final, many=True)

                return Response({
                    "report_id": report_id,
                    "total_assets": len(final),
                    "assets": serializer.data
                }, status=200)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": str(exc)}, status=500)
