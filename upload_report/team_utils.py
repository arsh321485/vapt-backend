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
