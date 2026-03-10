from django.urls import path
from .views import (
    UserLatestVulnerabilityRegisterAPIView,
    UserFixVulnerabilityCreateAPIView,
    UserFixVulnerabilityCardAPIView,
    UserFixVulnerabilityStepsAPIView,
    UserFixStepFeedbackAPIView,
    UserFixVulnerabilityFinalFeedbackAPIView,
    UserVulnerabilityTimelineAPIView,
)

urlpatterns = [
    # 1. Team-filtered vulnerability listing (main listing)
    path(
        "register/latest/vulns/",
        UserLatestVulnerabilityRegisterAPIView.as_view(),
        name="user-latest-vulns",
    ),

    # 2. Fix vulnerability create + list (per asset)
    path(
        "fix-vulnerability/report/<str:report_id>/asset/<str:host_name>/create/",
        UserFixVulnerabilityCreateAPIView.as_view(),
        name="user-fix-vuln-create",
    ),

    # 3. Fix card detail (by fix_vuln_id)
    path(
        "fix-vulnerability/<str:fix_vuln_id>/card/",
        UserFixVulnerabilityCardAPIView.as_view(),
        name="user-fix-vuln-card",
    ),

    # 4. Steps (GET = fetch, POST = complete next step)
    path(
        "fix-vulnerability/<str:fix_vuln_id>/step-complete/",
        UserFixVulnerabilityStepsAPIView.as_view(),
        name="user-fix-vuln-steps",
    ),

    # 5. Step feedback
    path(
        "fix-vulnerability/<str:fix_vuln_id>/feedback/",
        UserFixStepFeedbackAPIView.as_view(),
        name="user-fix-step-feedback",
    ),

    # 6. Final feedback (only after closed)
    path(
        "fix-vulnerability/<str:fix_vuln_id>/final-feedback/",
        UserFixVulnerabilityFinalFeedbackAPIView.as_view(),
        name="user-fix-final-feedback",
    ),

    # 7. Vulnerability timeline
    path(
        "fix-vulnerability/<str:fix_vuln_id>/timeline/",
        UserVulnerabilityTimelineAPIView.as_view(),
        name="user-vuln-timeline",
    ),
]
