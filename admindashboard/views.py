from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated  # change to AllowAny for testing

from .serializers import (
    TotalAssetsSerializer, AvgScoreSerializer,
    VulnerabilitiesSerializer, ReportSummarySerializer,
    MitigationTimelineSerializer, MeanTimeRemediateSerializer
)
from .utils import MongoContext, safe_float_from
from .utils import MongoContext, parse_timeline_to_hours, humanize_hours

NESSUS_COLLECTION = "nessus_reports"

try:
    from risk_criteria.models import RiskCriteria
except Exception:
    RiskCriteria = None

try:
    from users.models import User
except Exception:
    User = None

def _load_report(db, report_id):
    coll = db[NESSUS_COLLECTION]
    return coll.find_one({"report_id": str(report_id)})

def _get_latest_riskcriteria_for_admin_email(email):
    if not RiskCriteria or not User:
        return None
    try:
        user = User.objects.filter(email=email).first()
        if not user:
            return None
        rc = RiskCriteria.objects.filter(admin=user).order_by('-created_at').first()
        return rc
    except Exception:
        return None

def _get_latest_riskcriteria_for_user(user):
    if not RiskCriteria or not user:
        return None
    try:
        return RiskCriteria.objects.filter(admin=user).order_by('-created_at').first()
    except Exception:
        return None

class ReportTotalAssetsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]

                # Load report
                doc = coll.find_one(
                    {"report_id": str(report_id)},
                    {"vulnerabilities_by_host": 1}
                )

                if not doc:
                    return Response(
                        {"detail": "report not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                # ------- COUNT UNIQUE HOST NAMES -------
                hosts = set()

                for h in (doc.get("vulnerabilities_by_host") or []):
                    host_name = (h.get("host_name") or h.get("host") or "").strip()
                    if host_name:
                        hosts.add(host_name)

                total_assets = len(hosts)

                # Return result
                serializer = TotalAssetsSerializer({"total_assets": total_assets})
                return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# class ReportTotalAssetsAPIView(APIView):
#     permission_classes = [IsAuthenticated]

#     def get(self, request, report_id):
#         try:
#             with MongoContext() as db:
#                 doc = _load_report(db, report_id)
#                 if not doc:
#                     return Response({"detail":"report not found"}, status=status.HTTP_404_NOT_FOUND)
#                 total_hosts = doc.get("total_hosts") or 0
#                 try:
#                     total_assets = int(total_hosts)
#                 except Exception:
#                     try:
#                         total_assets = int(float(total_hosts))
#                     except Exception:
#                         total_assets = 0
#                 return Response(TotalAssetsSerializer({"total_assets": total_assets}).data)
#         except RuntimeError as rte:
#             return Response({"detail": str(rte)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#         except Exception as e:
#             return Response({"detail":"error", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ReportAvgScoreAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                doc = _load_report(db, report_id)
                if not doc:
                    return Response({"detail":"report not found"}, status=status.HTTP_404_NOT_FOUND)
                cvss_vals = []
                for host in doc.get("vulnerabilities_by_host") or []:
                    for v in (host.get("vulnerabilities") or []):
                        cv_raw = v.get("cvss_v3_base_score") or v.get("cvss") or v.get("cvss_score") or ""
                        num = safe_float_from(cv_raw)
                        if num is not None:
                            cvss_vals.append(num)
                avg = round(sum(cvss_vals)/len(cvss_vals), 2) if cvss_vals else None
                return Response(AvgScoreSerializer({"avg_score": avg}).data)
        except RuntimeError as rte:
            return Response({"detail": str(rte)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"detail":"error", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ReportVulnerabilitiesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                doc = _load_report(db, report_id)
                if not doc:
                    return Response({"detail":"report not found"}, status=status.HTTP_404_NOT_FOUND)
                counts = {"critical":0,"high":0,"medium":0,"low":0}
                for host in doc.get("vulnerabilities_by_host") or []:
                    for v in (host.get("vulnerabilities") or []):
                        risk = (v.get("risk_factor") or v.get("severity") or "").strip().lower()
                        if risk.startswith("crit"):
                            counts["critical"] += 1
                        elif risk.startswith("high"):
                            counts["high"] += 1
                        elif risk.startswith("med"):
                            counts["medium"] += 1
                        elif risk.startswith("low"):
                            counts["low"] += 1
                return Response(VulnerabilitiesSerializer(counts).data)
        except RuntimeError as rte:
            return Response({"detail": str(rte)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"detail":"error", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ReportSummaryAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                doc = _load_report(db, report_id)
                if not doc:
                    return Response({"detail":"report not found"}, status=status.HTTP_404_NOT_FOUND)

                # total_assets
                total_hosts = doc.get("total_hosts") or 0
                try:
                    total_assets = int(total_hosts)
                except Exception:
                    try:
                        total_assets = int(float(total_hosts))
                    except Exception:
                        total_assets = 0

                # vulnerabilities + cvss
                counts = {"critical":0,"high":0,"medium":0,"low":0}
                cvss_vals = []
                for host in doc.get("vulnerabilities_by_host") or []:
                    for v in (host.get("vulnerabilities") or []):
                        risk = (v.get("risk_factor") or v.get("severity") or "").strip().lower()
                        if risk.startswith("crit"):
                            counts["critical"] += 1
                        elif risk.startswith("high"):
                            counts["high"] += 1
                        elif risk.startswith("med"):
                            counts["medium"] += 1
                        elif risk.startswith("low"):
                            counts["low"] += 1
                        cv_raw = v.get("cvss_v3_base_score") or v.get("cvss") or v.get("cvss_score") or ""
                        num = safe_float_from(cv_raw)
                        if num is not None:
                            cvss_vals.append(num)

                avg = round(sum(cvss_vals)/len(cvss_vals), 2) if cvss_vals else None

                payload = {
                    "report_id": str(report_id),
                    "total_assets": total_assets,
                    "avg_score": avg,
                    "vulnerabilities": counts
                }
                return Response(ReportSummarySerializer(payload).data)
        except RuntimeError as rte:
            return Response({"detail": str(rte)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"detail":"error", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class ReportMitigationTimelineAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                doc = _load_report(db, report_id)
                if not doc:
                    return Response({"detail": "report not found"}, status=status.HTTP_404_NOT_FOUND)

                admin_email = doc.get("admin_email", "") or ""
                rc = None
                if admin_email:
                    rc = _get_latest_riskcriteria_for_admin_email(admin_email)
                if not rc:
                    rc = _get_latest_riskcriteria_for_user(getattr(request, "user", None))

                # strings (may be "", "Select", etc.)
                critical = getattr(rc, "critical", "") if rc else ""
                high     = getattr(rc, "high", "") if rc else ""
                medium   = getattr(rc, "medium", "") if rc else ""
                low      = getattr(rc, "low", "") if rc else ""

                # convert to hours and days
                ch = parse_timeline_to_hours(critical)
                hh = parse_timeline_to_hours(high)
                mh = parse_timeline_to_hours(medium)
                lh = parse_timeline_to_hours(low)

                total_hours = ch + hh + mh + lh
                total_days = round(total_hours / 24, 2)

                payload = {
                    "critical": critical,
                    "critical_hours": ch,
                    "critical_days": round(ch / 24, 2),
                    "high": high,
                    "high_hours": hh,
                    "high_days": round(hh / 24, 2),
                    "medium": medium,
                    "medium_hours": mh,
                    "medium_days": round(mh / 24, 2),
                    "low": low,
                    "low_hours": lh,
                    "low_days": round(lh / 24, 2),
                    "mitigation_timeline_total_hours": total_hours,
                    "mitigation_timeline_total_days": total_days
                }

                return Response(payload, status=status.HTTP_200_OK)

        except RuntimeError as rte:
            return Response({"detail": str(rte)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as exc:
            return Response({"detail": "unexpected error", "error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ReportMeanTimeRemediateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                doc = _load_report(db, report_id)
                if not doc:
                    return Response({"detail": "report not found"}, status=status.HTTP_404_NOT_FOUND)

                admin_email = doc.get("admin_email", "") or ""
                rc = None
                if admin_email:
                    rc = _get_latest_riskcriteria_for_admin_email(admin_email)
                if not rc:
                    rc = _get_latest_riskcriteria_for_user(getattr(request, "user", None))

                if not rc:
                    return Response({"detail": "no risk criteria found for report admin or current user"},
                                    status=status.HTTP_404_NOT_FOUND)

                # timeline hours
                ch = parse_timeline_to_hours(getattr(rc, "critical", "") or "")
                hh = parse_timeline_to_hours(getattr(rc, "high", "") or "")
                mh = parse_timeline_to_hours(getattr(rc, "medium", "") or "")
                lh = parse_timeline_to_hours(getattr(rc, "low", "") or "")
                mitigation_timeline_total_hours = ch + hh + mh + lh
                mitigation_timeline_total_days = round(mitigation_timeline_total_hours / 24, 2)

                # counts
                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for host in doc.get("vulnerabilities_by_host") or []:
                    for v in (host.get("vulnerabilities") or []):
                        risk = (v.get("risk_factor") or v.get("severity") or "").strip().lower()
                        if risk.startswith("crit"):
                            counts["critical"] += 1
                        elif risk.startswith("high"):
                            counts["high"] += 1
                        elif risk.startswith("med"):
                            counts["medium"] += 1
                        elif risk.startswith("low"):
                            counts["low"] += 1
                total_vulns = sum(counts.values())

                # weighted mean (hours)
                if total_vulns > 0:
                    total_hours_sum = (counts["critical"] * ch +
                                       counts["high"] * hh +
                                       counts["medium"] * mh +
                                       counts["low"] * lh)
                    mean_weighted_hours = float(total_hours_sum) / float(total_vulns)
                else:
                    mean_weighted_hours = 0.0

                # simple mean (non-zero timeline values)
                timeline_values = [x for x in (ch, hh, mh, lh) if x > 0]
                mean_simple_hours = float(sum(timeline_values)) / float(len(timeline_values)) if timeline_values else 0.0

                payload = {
                    "report_id": str(report_id),

                    # mitigation timeline totals
                    "mitigation_timeline_total_hours": mitigation_timeline_total_hours,
                    "mitigation_timeline_total_days": mitigation_timeline_total_days,
                    "mitigation_timeline_total_human": humanize_hours(mitigation_timeline_total_hours),

                    # mean times
                    "mean_time_weighted_hours": round(mean_weighted_hours, 2),
                    "mean_time_weighted_days": round(mean_weighted_hours / 24, 2),
                    "mean_time_weighted_human": humanize_hours(mean_weighted_hours),

                    "mean_time_simple_hours": round(mean_simple_hours, 2),
                    "mean_time_simple_days": round(mean_simple_hours / 24, 2),
                    "mean_time_simple_human": humanize_hours(mean_simple_hours),

                    "total_vulnerabilities": total_vulns,
                    "counts": counts
                }

                return Response(payload, status=status.HTTP_200_OK)

        except RuntimeError as rte:
            return Response({"detail": str(rte)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as exc:
            return Response({"detail": "unexpected error", "error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)