"""
Adaptive Card builders for the Teams admin-dashboard-channel onboarding
flow — the Teams equivalent of the Slack Block Kit builders in
users/views.py (_build_admin_welcome_blocks, _build_provide_scope_blocks,
_build_enter_scope_options_blocks, _build_admin_risk_criteria_prompt_blocks,
_nav_buttons_block). Same copy, same step order, same action names where a
direct equivalent exists — only the card format changes (Adaptive Card JSON
instead of Block Kit blocks), per "same as a Slack me kiya hai vese hi".

Every button is an Action.Submit whose `data` is echoed back verbatim as the
`value` field of the resulting Teams "message" activity — that's the field
TeamsBotMessagesView._handle_message already branches on.
"""

_SCHEMA = "http://adaptivecards.io/schemas/adaptive-card.json"
_VERSION = "1.4"

# Same option list + defaults as users/views.py's _RISK_LEVEL_OPTIONS /
# _RISK_CRITERIA_DEFAULTS — kept as a separate copy (not imported) so
# teams_bot has no import-time dependency on the Slack-side module for
# something this small; the values themselves must stay identical to the
# website/Slack dropdowns.
RISK_LEVEL_OPTIONS = [
    "1 Day", "2 Days", "3 Days", "4 Days", "5 Days", "6 Days",
    "1 Week", "2 Weeks", "3 Weeks", "4 Weeks", "5 Weeks",
]
RISK_CRITERIA_DEFAULTS = {
    "critical": "2 Days",
    "high": "4 Days",
    "medium": "2 Weeks",
    "low": "4 Weeks",
}


def _card(body, actions=None):
    card = {
        "$schema": _SCHEMA,
        "type": "AdaptiveCard",
        "version": _VERSION,
        "body": body,
        # Teams caps card width to a narrow default (~330px, leaving most of
        # the message pane empty) unless told otherwise — this is the
        # documented Teams-specific escape hatch to use the full available
        # width instead, which is what actually made the empty space on the
        # right go away and gave the nav row more room to fit on one line.
        "msteams": {"width": "Full"},
    }
    if actions:
        card["actions"] = actions
    return card


def _header(text):
    return {"type": "TextBlock", "text": text, "weight": "Bolder", "size": "Large", "wrap": True}


def _body_text(text):
    return {"type": "TextBlock", "text": text, "wrap": True, "spacing": "Medium"}


def _open_url_action(title, url, style=None):
    action = {"type": "Action.OpenUrl", "title": title, "url": url}
    if style:
        action["style"] = style
    return action


def _submit_action(title, action_id, extra_data=None, style=None):
    action = {
        "type": "Action.Submit",
        "title": title,
        "data": {"action_id": action_id, **(extra_data or {})},
    }
    if style:
        action["style"] = style  # "positive" is Adaptive Card's primary-button equivalent
    return action


def welcome_card():
    """Mirrors _build_admin_welcome_blocks()."""
    return _card(
        body=[
            _header("👋 Welcome to VaptFix, Admin"),
            _body_text(
                "You've been set up as the Workspace Admin for this organization. "
                "From here you will administer your vulnerability management program.\n\n"
                "To get started, upload your existing VA report right here — or provide "
                "scope and we'll run the assessment for you."
            ),
        ],
        actions=[_submit_action("📋 Provide Your Scope", "open_provide_scope", style="positive")],
    )


def provide_scope_card():
    """Mirrors _build_provide_scope_blocks()."""
    return _card(
        body=[
            _header("📋 Provide Your Scope"),
            _body_text(
                "Choose how you want to start — upload an existing scan report, "
                "or enter the assets VaptFix should test."
            ),
        ],
        actions=[
            _submit_action("📤 Upload Report", "open_upload_report", style="positive"),
            _submit_action("📋 Enter Your Scope", "open_enter_scope_options"),
        ],
    )


def enter_scope_options_card():
    """Mirrors _build_enter_scope_options_blocks()."""
    return _card(
        body=[
            _header("📋 Enter Your Scope"),
            _body_text("Add targets with a CSV file, or enter IPs/hosts manually."),
        ],
        actions=[
            _submit_action("📄 CSV File", "open_scope_csv", style="positive"),
            _submit_action("✍️ Manual Entry", "open_scope_manual"),
            _submit_action("← Back", "back_to_provide_scope"),
        ],
    )


def _risk_choice_set(risk_id, label, default_value):
    return {
        "type": "Input.ChoiceSet",
        "id": risk_id,
        "label": label,
        "value": default_value,
        "style": "compact",
        "choices": [{"title": opt, "value": opt} for opt in RISK_LEVEL_OPTIONS],
    }


def risk_criteria_form_card(existing=None):
    """
    The actual entry form — mirrors _build_risk_criteria_modal(): one
    dropdown per severity, pre-selected with the current value if the admin
    already has risk criteria on file, otherwise the same defaults Slack
    and the website use.
    """
    existing = existing or {}
    return _card(
        body=[
            _header("⚙️ Set Risk Criteria"),
            _body_text("How many days should each severity take to fix?"),
            _risk_choice_set("rc_critical", "Critical", existing.get("critical") or RISK_CRITERIA_DEFAULTS["critical"]),
            _risk_choice_set("rc_high", "High", existing.get("high") or RISK_CRITERIA_DEFAULTS["high"]),
            _risk_choice_set("rc_medium", "Medium", existing.get("medium") or RISK_CRITERIA_DEFAULTS["medium"]),
            _risk_choice_set("rc_low", "Low", existing.get("low") or RISK_CRITERIA_DEFAULTS["low"]),
        ],
        actions=[_submit_action("💾 Save", "submit_risk_criteria", style="positive")],
    )


def open_website_upload_card(purpose="report"):
    """
    Confirmed via real production activity dumps: a file attached to a
    Teams CHANNEL message never reaches the bot's messaging endpoint at all
    — only the message text/mention comes through, the file itself stays
    on SharePoint with no reference in the payload. This is a hard Teams
    platform limitation for channel-scope bots (personal 1:1 chat bots
    behave differently, but that's not this surface), not something fixable
    from here — so instead of asking for an in-chat attachment, this opens
    the same "Provide Your Scope" flow the website already has, in a
    browser tab, exactly the way several official Teams bots hand off to a
    full web form for anything more complex than a card can do.
    """
    from django.conf import settings
    frontend = getattr(settings, "FRONTEND_URL", "https://vaptfix.ai").rstrip("/")
    url = f"{frontend}/admin-upload-report"
    noun = "VA report" if purpose == "report" else "scope CSV"
    return _card(
        body=[
            _header("🌐 Continue on the VaptFix website"),
            _body_text(
                f"Teams doesn't let bots receive files posted in a channel, so upload your {noun} "
                "on the website instead — same account, opens in your browser."
            ),
        ],
        actions=[_open_url_action("📤 Open Upload Page", url, style="positive")],
    )


def manual_scope_form_card():
    return _card(
        body=[
            _header("✍️ Enter Your Scope"),
            _body_text("Enter targets as a comma-separated list of IPs or hostnames."),
            {"type": "Input.Text", "id": "manual_scope_targets", "isMultiline": True,
             "placeholder": "e.g. 10.0.0.1, 10.0.0.2, app.example.com"},
        ],
        actions=[_submit_action("💾 Save Scope", "submit_manual_scope", style="positive")],
    )


def text_result_card(title, message):
    """Generic small result/acknowledgement card (success or error)."""
    return _card(body=[_header(title), _body_text(message)])


def risk_criteria_prompt_card():
    """Mirrors _build_admin_risk_criteria_prompt_blocks()."""
    return _card(
        body=[
            _header("📊 Your first report is in!"),
            _body_text(
                "Before your dashboard opens, set your risk criteria — how many days "
                "each severity should take to fix (e.g. \"3 days\", \"1 week\")."
            ),
        ],
        actions=[_submit_action("⚙️ Set Risk Criteria", "open_risk_criteria", style="positive")],
    )


# Same tab set + order as SlackSlashCommandView._NAV_ITEMS, and the same
# internal action_id spelling (nav_home, nav_fix, ...) so any shared
# downstream data-formatting code keys off one consistent name across both
# platforms. Labels kept short on purpose (see _nav_button_columnset) —
# Teams renders these host-side and will still wrap onto a second line on a
# narrow pane no matter what the card says, but short labels in a ColumnSet
# give it the best real chance of staying on one row.
NAV_ITEMS = [
    ("nav_home", "🏠 Home"),
    ("nav_fix", "🔧 Fix"),
    ("nav_register", "📋 Register"),
    ("nav_automation", "🤖 Auto"),
    ("nav_team", "👥 Team"),
    ("nav_request", "📨 Ext."),
    ("nav_notification", "🔔 Alerts"),
    ("nav_download", "📥 Report"),
]


def _nav_button_columnset(active_action_id):
    """
    A single-row button bar built from a ColumnSet with narrow auto-width
    columns, each made clickable via selectAction — this packs noticeably
    tighter than Adaptive Cards' own `actions` array (which is what kept
    wrapping onto a second row before), though the final call on wrapping
    is still Teams' own host rendering, not something the card format can
    force absolutely.
    """
    columns = []
    for action_id, label in NAV_ITEMS:
        is_active = action_id == active_action_id
        columns.append({
            "type": "Column",
            "width": "auto",
            "verticalContentAlignment": "center",
            "selectAction": {"type": "Action.Submit", "data": {"action_id": action_id}},
            "items": [{
                "type": "TextBlock",
                "text": label,
                "wrap": False,
                "size": "Small",
                "weight": "Bolder" if is_active else "Default",
                "color": "accent" if is_active else "default",
                "horizontalAlignment": "center",
            }],
        })
    return {"type": "ColumnSet", "columns": columns, "spacing": "Medium", "separator": True}


def nav_buttons_card(active_action_id="nav_home", extra_body=None):
    """
    The persistent navbar row — placed at the TOP of the card (matching the
    reference design's own header-tabs layout), with that tab's content
    below it. Each nav click replaces the whole card in place (see
    onboarding.replace_active_card) rather than appending a new one.
    """
    body = [_nav_button_columnset(active_action_id)]
    body.extend(extra_body or [])
    return _card(body=body)


# ─── Home dashboard card ────────────────────────────────────────────────
# Approximates the reference design (Microsoft -Admin/home.html) as closely
# as Adaptive Cards allow — Teams cards have no canvas/chart rendering, so
# the bar/donut charts there become colored stat rows and chip rows here
# instead; same information, same grouping, just no literal chart images.

_SEV_ORDER = ("critical", "high", "medium", "low")
_SEV_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
_SEV_COLORS = {"critical": "attention", "high": "warning", "medium": "warning", "low": "good"}


def _section_title(text):
    return {"type": "TextBlock", "text": text, "weight": "Bolder", "size": "Medium", "spacing": "Large", "wrap": True}


def _stat_container(icon, label, value, desc=None):
    items = [
        {"type": "TextBlock", "text": f"{icon}  {label}", "size": "Small", "weight": "Bolder",
         "color": "accent", "wrap": True, "spacing": "None"},
        {"type": "TextBlock", "text": str(value), "size": "ExtraLarge", "weight": "Bolder", "spacing": "Small", "wrap": True},
    ]
    if desc:
        items.append({"type": "TextBlock", "text": desc, "size": "Small", "isSubtle": True, "spacing": "None", "wrap": True})
    return {"type": "Container", "style": "emphasis", "items": items, "spacing": "Small"}


def _stat_row(*stats):
    """stats: list of (icon, label, value, desc) tuples, laid out as equal-width columns."""
    return {
        "type": "ColumnSet",
        "spacing": "Medium",
        "columns": [
            {"type": "Column", "width": "stretch", "items": [_stat_container(*s)]}
            for s in stats
        ],
    }


def _severity_chip_row(counts: dict):
    columns = []
    for sev in _SEV_ORDER:
        columns.append({
            "type": "Column",
            "width": "stretch",
            "items": [
                {"type": "TextBlock", "text": f"{_SEV_ICONS[sev]} {sev.title()}", "size": "Small", "weight": "Bolder", "wrap": True},
                {"type": "TextBlock", "text": str(counts.get(sev, 0) or 0), "size": "Large", "weight": "Bolder", "color": _SEV_COLORS[sev]},
            ],
        })
    return {"type": "ColumnSet", "columns": columns, "spacing": "Small"}


def _mitigation_timeline_row(timeline: dict):
    columns = []
    for sev in _SEV_ORDER:
        info = timeline.get(sev) or {}
        label = info.get("remaining_label") or "—"
        is_overdue = info.get("status") == "overdue"
        color = "attention" if is_overdue else _SEV_COLORS[sev]
        columns.append({
            "type": "Column",
            "width": "stretch",
            "items": [{
                "type": "TextBlock",
                "text": f"{sev.title()} — {label}",
                "size": "Small", "weight": "Bolder", "color": color, "wrap": True,
            }],
        })
    return {"type": "ColumnSet", "columns": columns, "spacing": "Small"}


def _support_requests_row(support: dict):
    items = [
        ("📥", "Total Requests", support.get("total", 0)),
        ("⏳", "Pending", support.get("pending", 0)),
        ("✅", "Closed", support.get("closed", 0)),
    ]
    columns = []
    for icon, label, val in items:
        columns.append({
            "type": "Column",
            "width": "stretch",
            "items": [
                {"type": "TextBlock", "text": f"{icon} {label}", "size": "Small", "isSubtle": True, "wrap": True},
                {"type": "TextBlock", "text": str(val or 0), "size": "Large", "weight": "Bolder", "spacing": "None"},
            ],
        })
    return {"type": "ColumnSet", "columns": columns, "spacing": "Small"}


def home_dashboard_card_body(data: dict):
    """
    `data` is the same shape AdminDashboardSummaryAPIView returns (one key
    per metric, each holding that sub-view's own payload) — build the
    full Home tab body from it. Returns a list of Adaptive Card body
    elements (not a full card), same convention as the other *_body
    helpers — callers pass this as nav_buttons_card's extra_body.
    """
    total_assets = (data.get("total_assets") or {}).get("total_assets")
    avg_score = (data.get("avg_score") or {}).get("avg_score")
    mttr_label = ((data.get("mean_time_remediate") or {}).get("mean_time_to_remediate") or {}).get("label")
    vulns = data.get("vulnerabilities") or {}
    fixed = data.get("vulnerabilities_fixed") or {}
    fixed_counts = {sev: fixed.get(f"{sev}_fixed", 0) for sev in _SEV_ORDER}
    timeline = data.get("mitigation_timeline") or {}
    support = data.get("support_requests") or {}

    body = [
        _header("🏠 VaptFix Admin Dashboard"),
        _body_text("Overall summary — assets, vulnerabilities, mitigation timeline, mean fix time and support tickets."),
        _stat_row(
            ("💻", "TOTAL ASSETS", total_assets if total_assets is not None else "—", "Monitored endpoints"),
            ("⚠️", "AVG RISK SCORE", f"{avg_score} / 10" if avg_score is not None else "—", "Higher = more urgent"),
            ("⏱️", "MEAN TIME TO REMEDIATE", mttr_label or "—", "Average resolution time"),
        ),
        _section_title("📊 Vulnerabilities by Severity"),
        _severity_chip_row(vulns),
        _section_title(f"✅ Vulnerabilities Fixed: {fixed.get('total_fixed', 0)}"),
        _severity_chip_row(fixed_counts),
    ]
    if timeline:
        body.append(_section_title("🕐 Mitigation Timeline"))
        body.append(_mitigation_timeline_row(timeline))
    if support:
        body.append(_section_title("🎫 Support Requests"))
        body.append(_support_requests_row(support))
    return body


def dashboard_image_card_body(team_id, kind="dashboard", title=None, extra_params=None):
    """
    Real bento-grid dashboard, rendered server-side to a PNG and shown as
    an Adaptive Card Image — reuses the exact same rendering pipeline
    already built for Slack (see teams_bot.views.TeamsDashboardImageView),
    so this looks exactly like the reference design, not a hand-built
    approximation. `t=` cache-busts so re-posting always shows fresh data;
    the signed token is short-lived (10 min, minted fresh every call).
    """
    import time
    from urllib.parse import quote
    from django.conf import settings
    from users.views import _dashboard_image_signer

    token = _dashboard_image_signer().sign(team_id)
    backend = getattr(settings, "VAPTFIX_BACKEND_URL", "https://vaptbackend.secureitlab.com")
    url = f"{backend}/api/admin/users/teams/dashboard-image/?token={quote(token)}&kind={kind}&t={int(time.time())}"
    for k, v in (extra_params or {}).items():
        if v is not None and str(v) != "":
            url += f"&{quote(str(k))}={quote(str(v))}"
    return [
        {"type": "Image", "url": url, "size": "Stretch", "altText": title or "VaptFix Dashboard"},
    ]


# Fix tab's own sub-nav — All Assets / All Vulns / Common Vulns (matches
# Slack's _FIX_SUBTABS, same action_id spelling so nothing else has to
# guess at the mapping).
FIX_SUBTABS = [
    ("fix_sub_assets", "🖥 All Assets"),
    ("fix_sub_vulns", "📋 All Vulns"),
    ("fix_sub_common", "🧩 Common Vulns"),
]


def _fix_subnav_columnset(active_sub):
    columns = []
    for action_id, label in FIX_SUBTABS:
        is_active = action_id == active_sub
        columns.append({
            "type": "Column",
            "width": "auto",
            "verticalContentAlignment": "center",
            "selectAction": {"type": "Action.Submit", "data": {"action_id": action_id}},
            "items": [{
                "type": "TextBlock", "text": label, "wrap": False, "size": "Small",
                "weight": "Bolder" if is_active else "Default",
                "color": "accent" if is_active else "default",
                "horizontalAlignment": "center",
            }],
        })
    return {"type": "ColumnSet", "columns": columns, "spacing": "Medium", "separator": True}


# Common Vulns' own team-filter row — matches Microsoft -Admin/commonvuln.html's tabs.
COMMON_VULNS_TEAMS = [
    ("patch", "Patch Management"),
    ("config", "Configuration Management"),
    ("network", "Network Security"),
    ("arch", "Architectural Flaws"),
]


def _common_vulns_team_columnset(active_team):
    columns = []
    for key, label in COMMON_VULNS_TEAMS:
        is_active = key == active_team
        columns.append({
            "type": "Column",
            "width": "auto",
            "verticalContentAlignment": "center",
            "selectAction": {"type": "Action.Submit", "data": {"action_id": "fix_common_team", "team": key}},
            "items": [{
                "type": "TextBlock", "text": label, "wrap": False, "size": "Small",
                "weight": "Bolder" if is_active else "Default",
                "color": "accent" if is_active else "default",
                "horizontalAlignment": "center",
            }],
        })
    return {"type": "ColumnSet", "columns": columns, "spacing": "Medium", "separator": True}


def fix_tab_body(team_id, active_sub="fix_sub_assets", common_team="config"):
    """
    Full Fix-tab body: its own sub-nav row (All Assets/All Vulns/Common
    Vulns) followed by that sub-tab's real content, rendered the same
    image-snapshot way as Home/Team (see dashboard_image_card_body) —
    matches Microsoft -Admin/allassets.html, allvuln.html, commonvuln.html.
    """
    body = [_fix_subnav_columnset(active_sub)]
    if active_sub == "fix_sub_vulns":
        body.extend(dashboard_image_card_body(team_id, kind="allvulns", title="All Vulnerabilities"))
    elif active_sub == "fix_sub_common":
        body.append(_common_vulns_team_columnset(common_team))
        body.extend(dashboard_image_card_body(team_id, kind="commonvulns", title="Common Vulnerabilities", extra_params={"team": common_team}))
    else:
        body.extend(dashboard_image_card_body(team_id, kind="assets", title="All Assets"))
    return body
