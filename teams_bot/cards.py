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
# platforms.
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


def nav_buttons_card(active_action_id="nav_home", extra_body=None):
    """
    The persistent navbar row — Teams doesn't support Slack's "replace
    message in place" pattern the same way, so each nav click sends a NEW
    card reply containing the navbar again plus that tab's content
    (extra_body), rather than editing a pinned message.
    """
    actions = [
        _submit_action(label, action_id, style=("positive" if action_id == active_action_id else None))
        for action_id, label in NAV_ITEMS
    ]
    return _card(body=extra_body or [], actions=actions)
