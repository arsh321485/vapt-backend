"""
Adaptive Card builders for the Teams admin-dashboard-channel onboarding
flow — the Teams equivalent of the Slack Block Kit builders in
users/views.py (_build_admin_welcome_blocks, _build_provide_scope_blocks,
_build_enter_scope_options_blocks, _build_admin_risk_criteria_prompt_blocks,
_nav_buttons_block). Same copy, same step order, same action names where a
direct equivalent exists — only the card format changes (Adaptive Card JSON
instead of Block Kit blocks), per "same as a Slack me kiya hai vese hi".

Every button is an Action.Execute (Adaptive Card Universal Actions) whose
`data` is echoed back verbatim in the resulting `invoke` activity
(name="adaptiveCard/action") — TeamsBotMessagesView._handle_adaptive_card_invoke
reads it from `value.action.data`. Action.Execute (not the older
Action.Submit) is what lets a click swap the card in place with zero
flicker and, critically, without Teams showing its "Your response was
sent to the app" toast on every click — that toast is baked into
Action.Submit's fire-and-forget flow and Teams' own docs name
Action.Execute + a synchronous invoke response as the only way around it.
"""

import logging
logger = logging.getLogger(__name__)

_SCHEMA = "http://adaptivecards.io/schemas/adaptive-card.json"
# Stayed on 1.4 deliberately — a 1.5-only ActionSet "orientation" property
# was tried for the tab bars and, along with the (already-reverted)
# `requires` field, the whole nav row stopped rendering in real Teams
# testing. Not confirmed which of the two actually caused it, so both are
# gone now rather than guessing further without being able to see the
# live client. pill_columnset uses a ColumnSet of Action.Execute buttons
# instead (see there) — proven to render (that was the working layout
# this whole epic has been tested against) while still using real buttons.
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


def _execute_action(title, data, style=None):
    """Action.Submit — explicit tradeoff, chosen deliberately over
    Action.Execute: Action.Execute's synchronous invoke round-trip is what
    greys out the WHOLE card for the ~1-2s a click is in flight (confirmed
    real, not fixable from card JSON — tried "requires": {"adaptiveCards":
    "1.3"} as a workaround, which instead made the whole nav row vanish,
    a worse regression, and was reverted). Action.Submit doesn't grey
    anything, but Teams always shows a "Your response was sent to the
    app" toast on every click — no card-JSON setting suppresses that
    either. Given a straight choice between the two (real, live-tested),
    the toast was picked over the grey-out.

    This one function is the single place every button in the whole
    teams_bot module is built from, so this is genuinely the only edit a
    switch back to Action.Execute (or another future option) needs.
    _handle_message's existing `if activity.get("value")` branch already
    handles Action.Submit for both admin and member dispatch — this isn't
    new wiring, just switching which action `type` reaches it."""
    action = {
        "type": "Action.Submit",
        "title": title,
        "data": data,
    }
    if style:
        action["style"] = style  # "positive" is Adaptive Card's primary-button equivalent
    return action


def _submit_action(title, action_id, extra_data=None, style=None):
    return _execute_action(title, {"action_id": action_id, **(extra_data or {})}, style=style)


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


def open_website_upload_card(purpose="report", admin=None):
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

    Carries the same signed admin-handoff token the Slack "Upgrade plan"
    link uses (see users.views._slack_pricing_handoff_signer /
    SlackPricingHandoffView) — confirmed via real testing that this exact
    class of bug (a bare link with no admin identity) made the website
    side show $0.00/0 assets, since it had no way to know who was
    visiting without an existing browser login session.
    """
    from django.conf import settings
    frontend = getattr(settings, "FRONTEND_URL", "https://vaptfix.ai").rstrip("/")
    url = f"{frontend}/admin-upload-report"
    if admin is not None:
        try:
            from users.views import _slack_pricing_handoff_signer
            from urllib.parse import quote
            handoff_token = _slack_pricing_handoff_signer().sign(str(admin.id))
            url = f"{url}?admin_token={quote(handoff_token)}"
        except Exception:
            logger.exception("[TeamsBot] failed to build signed handoff token for upload link")
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
# platforms. Full names kept (not shortened) per explicit request — real
# Action.Execute buttons get a narrow, roughly-uniform rendered width in
# Teams regardless of label length, so all 8 in one row truncated these;
# see _nav_button_columnset for how that's solved (two rows) instead of
# shortening the text.
NAV_ITEMS = [
    ("nav_home", "🏠 Home"),
    ("nav_fix", "🔧 Fix"),
    ("nav_register", "📋 Register"),
    ("nav_automation", "🤖 Automations"),
    ("nav_team", "👥 Team"),
    ("nav_request", "📨 Timeline Ext."),
    ("nav_notification", "🔔 Reminder"),
    ("nav_download", "📥 Download Report"),
]


def pill_columnset(options, active_key, build_data, stretch=True, separator=True):
    """
    Generic single-row tab bar — a ColumnSet of narrow auto-width columns,
    each holding one real Action.Execute button (an ActionSet with a
    single action inside), the active one styled "positive" (filled).

    This is the proven-working layout (ColumnSet + msteams.width:Full's
    trailing stretch column) this whole epic has actually been tested
    against, just with each column's content upgraded from a plain
    clickable TextBlock to a real button — a straight ActionSet with
    orientation="Horizontal" was tried first and made the entire row stop
    rendering in real Teams testing, so this sticks to the combination
    that's confirmed to work rather than the untested one.

    `options`: [(key, label), ...]. `build_data(key)` returns the click
    payload dict for that button (whatever teams_bot.actions.handle_card_action
    needs to route it) — kept as a callback rather than a fixed shape since
    every caller's payload fields differ (action_id, offset, filters, ...).
    `separator`: pass False for a row stacked directly under another pill
    row (see _nav_button_columnset) so there isn't a divider line between
    them.
    """
    columns = []
    for key, label in options:
        is_active = key == active_key
        columns.append({
            "type": "Column",
            "width": "auto",
            "verticalContentAlignment": "center",
            "items": [{
                "type": "ActionSet",
                "actions": [_execute_action(label, build_data(key), style="positive" if is_active else None)],
            }],
        })
    if stretch:
        columns.append({"type": "Column", "width": "stretch", "items": []})
    row = {"type": "ColumnSet", "columns": columns, "spacing": "Medium"}
    if separator:
        row["separator"] = True
    return row


def two_row_pill_columnset(options, active_key, build_data, split=None):
    """
    Same real-button tab bar as pill_columnset, but split across TWO rows
    instead of cramming everything into one. Real Action.Execute buttons
    in Teams get a narrow, roughly-uniform rendered width regardless of
    label length — confirmed via real testing that longer full labels
    (the top nav's "Automations"/"Timeline Ext."/"Reminder"/"Download
    Report", Reminder's own 5 bucket names) truncated badly in a single
    row. Splitting into two rows gives every button real room for its
    full label instead of shortening any of them. `split` defaults to
    half the options (rounded up).
    """
    if split is None:
        split = (len(options) + 1) // 2
    return {
        "type": "Container",
        # Shaded background + inset padding so the two stacked rows read
        # as one cohesive toolbar block, not two loose rows of buttons —
        # requested after the nav bar became two rows instead of one.
        "style": "emphasis",
        "bleed": True,
        "spacing": "Medium",
        "separator": True,
        "items": [
            # stretch=True on both (not just the first) — this is often
            # the first body element on a card, so whichever row ends up
            # deciding the card's overall claimed width needs the trailing
            # stretch column, and keeping it on both is simpler than
            # reasoning about which one that'll be in a given renderer.
            pill_columnset(options[:split], active_key, build_data, stretch=True),
            pill_columnset(options[split:], active_key, build_data, stretch=True, separator=False),
        ],
    }


def _nav_button_columnset(active_action_id):
    """The persistent top tab bar — see two_row_pill_columnset for why
    this is two rows of 4 instead of one row of 8."""
    return two_row_pill_columnset(NAV_ITEMS, active_action_id, lambda action_id: {"action_id": action_id}, split=4)


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


def freemium_upgrade_banner_items(admin, team_id):
    """
    Adaptive Card items (TextBlock + Upgrade button) shown above the Home
    dashboard image once a Freemium admin has closed every currently-
    visible finding on a report that still has hosts waiting behind the
    plan's asset/vuln caps. Reuses
    admindashboard.views._freemium_upgrade_prompt directly (same
    eligibility check the website dashboard and Slack's Home tab use) so
    Teams never disagrees with either about when this should show.
    Upgrading unlocks the rest of that same report automatically — no
    re-upload — see billing/stripe_service.py and
    upload_report/views.py's unlock_freemium_hosts_for_admin. Returns []
    when not eligible (or on any lookup failure — never blocks Home from
    rendering).
    """
    try:
        from admindashboard.views import _freemium_upgrade_prompt
        prompt = _freemium_upgrade_prompt(admin)
        if not prompt.get("eligible"):
            return []
        return [
            {
                "type": "TextBlock",
                "text": f"🔓 {prompt['message']}",
                "wrap": True,
                "weight": "Bolder",
                "color": "good",
                "spacing": "Medium",
            },
            {
                "type": "ActionSet",
                "actions": [_open_url_action(
                    "⭐ Upgrade to Premium",
                    prompt.get("upgrade_url", "https://vaptfix.ai/pricingplan"),
                    style="positive",
                )],
            },
        ]
    except Exception:
        logger.exception(f"[FreemiumBanner] Teams banner check failed for team_id={team_id}")
        return []


# Fix tab's own sub-nav — All Assets / All Vulns / Common Vulns (matches
# Slack's _FIX_SUBTABS, same action_id spelling so nothing else has to
# guess at the mapping).
FIX_SUBTABS = [
    ("fix_sub_assets", "🖥 All Assets"),
    ("fix_sub_vulns", "📋 All Vulns"),
    ("fix_sub_common", "🧩 Common Vulns"),
]


def _fix_subnav_columnset(active_sub):
    return pill_columnset(FIX_SUBTABS, active_sub, lambda action_id: {"action_id": action_id})


# Common Vulns' own team-filter row — matches Microsoft -Admin/commonvuln.html's tabs.
COMMON_VULNS_TEAMS = [
    ("patch", "Patch Management"),
    ("config", "Configuration Management"),
    ("network", "Network Security"),
    ("arch", "Architectural Flaws"),
]


def _common_vulns_team_columnset(active_team):
    # All 4 real team names ("Configuration Management", 25 chars) crammed
    # into one row of narrow auto-width columns truncated mid-word — same
    # reasoning as the top nav bar and Reminder's own two-row split.
    return two_row_pill_columnset(COMMON_VULNS_TEAMS, active_team, lambda key: {"action_id": "fix_common_team", "team": key}, split=2)


# Full Fix-tab body building (sub-nav + real, clickable content) now lives
# in teams_bot.fix_tab.fix_tab_body — it needs `admin` (not just team_id) to
# fetch rows in-process and build native drill-down rows, not just a PNG
# image URL. This module still supplies the widgets fix_tab.py builds on:
# _fix_subnav_columnset, _common_vulns_team_columnset, COMMON_VULNS_TEAMS.
