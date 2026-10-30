"""
Shared, reusable rule-based team classifier.

Real bug report: dozens of "vulnerabilities/assets grouped by team" views
across the app (Team Performance, Common Vulnerabilities, Register, All
Assets/All Vulnerabilities, dashboard totals, download report — admin AND
user sides) build their team grouping purely from
vulnerability_cards.assigned_team, the AI's own classification, written by
a slow BACKGROUND job (_auto_generate_cards_bg) that can take many minutes
to work through a large report. Until a vulnerability's card is generated,
almost every one of those views either silently excluded it entirely or
dumped it into an "Unassigned" bucket — so right after a big upload, real
data across the whole system looked wrong/incomplete until AI generation
fully caught up.

This mirrors the keyword logic already proven correct in
adminregister/userregister's FixVulnerabilityStepsAPIView._infer_assigned_
team (the one place this was already handled), reconciled with
automation_scripts_api's _infer_team_from_name additions (cisco ios/rce/
denial of service, icmp/nla/terrapin) into one single, shared,
importable version — previously there were 4 independent, divergent
copies of this same idea and none of them was actually reusable.

Use infer_assigned_team() anywhere a vulnerability_cards lookup for a
given plugin_name comes back empty (no card yet, or a card with no/
invalid assigned_team) — it's deterministic, has no AI/network call, and
always returns one of the 4 known teams, so "no card yet" never has to
mean "invisible" or "miscounted" to any consumer.
"""

TEAM_NETWORK_SECURITY = "Network Security"
TEAM_PATCH_MANAGEMENT = "Patch Management"
TEAM_ARCHITECTURAL_FLAWS = "Architectural Flaws"
TEAM_CONFIGURATION_MANAGEMENT = "Configuration Management"

# Real feature request: an admin can additionally create their own custom
# team(s) (users_details.models.CustomTeam), unlimited, name typed freely —
# alongside these 4 fixed/auto-classified ones, which stay exactly as they
# are. A vulnerability's assigned_team/infer_assigned_team() output is
# ALWAYS one of these 4 — never a custom team's name — so this set is the
# single, shared "is this a fixed team, or a custom one" check every
# team-scoped view (userasset/views.py, users_details/views.py's
# ReportAssetsVulnsAPIView, users/views.py's Slack team channels) uses to
# decide: match by classification (fixed team) vs. show everything (custom
# team, which has no classification pool of its own by design).
FIXED_TEAMS = {
    TEAM_NETWORK_SECURITY,
    TEAM_PATCH_MANAGEMENT,
    TEAM_ARCHITECTURAL_FLAWS,
    TEAM_CONFIGURATION_MANAGEMENT,
}


def is_fixed_team(team_name: str) -> bool:
    """True for one of the 4 auto-classified teams; False for anything
    else (a custom team name, or empty/unknown)."""
    return (team_name or "").strip() in FIXED_TEAMS


def custom_team_explicit_assets(admin_id, team_name) -> set:
    """
    Every host_name ever checkbox-assigned to this CUSTOM team via the Add
    User picker's role_assignments["assets"] (users_details.models.
    UserDetail) — across every member ever added with this team in their
    Member_role, not just one viewer's own record, since the team's asset
    pool is shared by everyone on it.

    Real bug report: a custom team's "clean" (zero-vulnerability) assets
    never showed up anywhere team-scoped (dashboard totals, asset list)
    even when explicitly checkbox-selected for that team — assigning a
    team to a VULNERABILITY (vulnerability_cards.additional_teams, see
    users_details.views._apply_role_assignments_to_cards) is the only
    classification mechanism a custom team has, and a clean host has no
    vulnerability card at all to tag. Use this as an EXTRA source of
    "this host belongs to this custom team", alongside whatever the
    plugin_team_map/additional_teams route already finds.

    Never needed for a fixed team — those already get every clean host
    for free (see is_fixed_team's own callers in userdashboard/userasset).
    """
    if not admin_id or not team_name:
        return set()
    from users_details.models import UserDetail
    hosts = set()
    for detail in UserDetail.objects.filter(admin__id=admin_id, Member_role__contains=team_name):
        ra = detail.role_assignments or {}
        # Flat shape (Slack/Teams) has "assets" at the top level; the
        # website's Add User picker instead nests it under the team name
        # — {team_name: {"assets": [...], ...}} — see the matching fix in
        # users_details.views._apply_role_assignments_to_cards.
        assets = ra.get("assets")
        if assets is None:
            nested = ra.get(team_name)
            assets = (nested or {}).get("assets") if isinstance(nested, dict) else None
        for h in (assets or []):
            h = (h or "").strip()
            if h:
                hosts.add(h)
    return hosts


def infer_assigned_team(vulnerability_name: str) -> str:
    """
    Best-effort, deterministic team classification from a vulnerability's
    name alone. Always returns one of the 4 known teams (defaults to
    Configuration Management when nothing else matches).
    """
    name = (vulnerability_name or "").lower()
    if any(k in name for k in (
        "ssl", "tls", "certificate", "port", "firewall", "network", "dns",
        "http", "ftp", "smtp", "redis", "memcached", "open port", "unencrypted",
        "cleartext", "cipher", "protocol", "snmp", "telnet", "ssh",
        "icmp", "nla", "terrapin",
    )):
        return TEAM_NETWORK_SECURITY
    if any(k in name for k in (
        "patch", "update", "version", "outdated", "cve-", "upgrade",
        "end-of-life", "unsupported", "obsolete",
        "cisco ios", "rce", "remote code execution", "denial of service",
    )):
        return TEAM_PATCH_MANAGEMENT
    if any(k in name for k in (
        "injection", "xss", "csrf", "cross-site", "sql injection",
        "authentication", "authorization", "session", "cookie", "oauth",
        "architectural", "design flaw", "logic flaw", "default credential",
    )):
        return TEAM_ARCHITECTURAL_FLAWS
    return TEAM_CONFIGURATION_MANAGEMENT
