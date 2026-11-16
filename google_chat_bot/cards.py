"""
Cards v2 JSON builders for the Google Chat bot — the Chat equivalent of
teams_bot/cards.py (Adaptive Cards) and the Slack integration's Block
Kit builders. Only the shared scaffolding (card envelope, buttons, the
persistent nav row) lives here for now — per-tab card bodies (Fix,
Register, Timeline Extension, Reminder, Support, Automations) will be
added incrementally once a real space is wired up for testing, the same
way teams_bot grew its own tab files (fix_tab.py, register_tab.py, ...)
one at a time rather than all at once.
"""

# Same 8 tabs/order as the admin-side Teams/Slack nav (teams_bot.cards.
# NAV_ITEMS) — kept in sync here so a future admin-side Google Chat nav
# matches both other platforms exactly.
NAV_ITEMS = [
    ("nav_home", "Home"),
    ("nav_fix", "Fix"),
    ("nav_register", "Register"),
    ("nav_extend", "Timeline Ext."),
    ("nav_support", "Support Status"),
    ("nav_fixed", "Fixed"),
    ("nav_reminder", "Reminder"),
    ("nav_automations", "Automations"),
]


def _card(header: dict = None, sections: list = None) -> dict:
    card = {"sections": sections or []}
    if header:
        card["header"] = header
    return card


def card_header(title: str, subtitle: str = None, image_url: str = None) -> dict:
    header = {"title": title}
    if subtitle:
        header["subtitle"] = subtitle
    if image_url:
        header["imageUrl"] = image_url
    return header


def button(text: str, action_function: str, parameters: dict = None) -> dict:
    """One Cards v2 button — `parameters` become the ActionParameter list
    Chat hands back on a CARD_CLICKED event (the direct equivalent of an
    Adaptive Card Action.Execute's `data`, or a Slack button's `value`)."""
    params = [{"key": k, "value": str(v)} for k, v in (parameters or {}).items()]
    return {
        "text": text,
        "onClick": {"action": {"function": action_function, "parameters": params}},
    }


def button_list_section(buttons: list, header: str = None) -> dict:
    section = {"widgets": [{"buttonList": {"buttons": buttons}}]}
    if header:
        section["header"] = header
    return section


def nav_buttons_section(active_nav_id: str = "nav_home") -> dict:
    """The persistent top nav — one button per tab, same tab set as the
    Teams/Slack admin nav. Google Chat's buttonList wraps automatically
    (no Teams-style mobile truncation risk from a fixed-column layout),
    so this doesn't need a two-row variant the way teams_bot.cards does."""
    buttons = [
        button(("● " if nav_id == active_nav_id else "") + label, "handleNav", {"nav_id": nav_id})
        for nav_id, label in NAV_ITEMS
    ]
    return button_list_section(buttons)


def text_paragraph_widget(text: str) -> dict:
    return {"textParagraph": {"text": text}}
