# Automation Fix — Freemium Lock Indicator (Frontend)

Backend is done and deployed. Every endpoint that returns an automation
script's detail (what renders the "Automation Fix" tab/screen) now tells
you up front whether the current account's plan allows it at all.

## Affected endpoints (admin + user side)

- `GET /api/admin/automation-scripts/match/<plugin_id>/`
- `POST /api/admin/automation-scripts/match/bulk/`
- `POST /api/admin/automation-scripts/match/by-name/`
- `GET /api/user/automation-scripts/match/<plugin_id>/`
- `POST /api/user/automation-scripts/match/bulk/`
- `POST /api/user/automation-scripts/match/by-name/`

(Route names as configured in your api client — these are the view functions; confirm exact paths against `automation_scripts_api/urls.py` if different.)

## New response fields

**Single-script endpoints** — the fields sit at the top level, alongside the script's own fields:
```json
{
  "matched": true,
  "plugin_id": 10114,
  "vulnerability": "...",
  "script_description": "...",
  ...all the other existing script fields...,
  "premium_required": true,
  "message": "Automation scripts are not available on the Freemium plan. Upgrade to Premium."
}
```

**Bulk / by-name endpoints** — the fields sit once at the top of the response, next to `results` (not per-item — it's one plan check for the whole request, not per script):
```json
{
  "results": [ { "matched": true, ... }, { "matched": true, ... } ],
  "premium_required": true,
  "message": "Automation scripts are not available on the Freemium plan. Upgrade to Premium."
}
```

## What to do with it

- `premium_required: false` → render the Automation Fix screen exactly as today, `message` will be `null`.
- `premium_required: true` → the script content (description, recommended approach, etc.) is still present in the response — you can still show it as read-only/preview if you want — but:
  - Show the `message` text as a lock/upgrade notice (e.g. a banner or replacing the Download button).
  - Hide or disable the Download button — the actual download endpoint (`/download/<plugin_id>/`) already rejects it with a 403 on this plan, so a visible-but-broken button is worse than no button.
  - Point the notice at the pricing page (`https://vaptfix.ai/pricingplan`), same as the rest of the app's upgrade prompts.

This is the exact same signal Slack's Automation Fix already shows (a 🔒 lock message) — matching that on the website closes the last place this was inconsistent.
