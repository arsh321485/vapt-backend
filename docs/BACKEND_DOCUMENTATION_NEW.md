# VAPTFix Backend — Complete Documentation (Updated)

This document is a **complete guide** to the VAPTFix backend. If you have zero prior knowledge of the VAPTFix codebase, this document will help you understand:

- What the project is and how it works
- What technologies are used
- Where things live in the folder / app structure
- Request flow, auth, database
- What each Django app does
- **A full deep-dive into the Slack integration** (new — this is the most detailed part, since it's where most recent development happened)
- How to run it locally

> **Note:** This file is an updated version of `docs/BACKEND_DOCUMENTATION.md`. That earlier file (written 14 Jul 2026) was already fairly accurate, but since then `users/views.py` grew by ~4,400 lines (Slack Home/Register/All-Vulns/Support tabs, team cards, dashboard images) — this file covers all of that. Both files live in `docs/`; treat this newer one as the current source of truth.

---

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [Tech Stack](#2-tech-stack)
3. [High-Level Architecture](#3-high-level-architecture)
4. [Project Folder Structure](#4-project-folder-structure)
5. [Roles: Admin vs Team Member vs Superadmin](#5-roles-admin-vs-team-member-vs-superadmin)
6. [Authentication & JWT](#6-authentication--jwt)
7. [Database (MongoDB) — Two Layers](#7-database-mongodb--two-layers)
8. [End-to-End Business Flow](#8-end-to-end-business-flow)
9. [Django Apps — Detail](#9-django-apps--detail)
10. [API URL Map](#10-api-url-map)
11. [Report Upload & Parsing Pipeline](#11-report-upload--parsing-pipeline)
12. [AI Mitigation (CrewAI)](#12-ai-mitigation-crewai)
13. [Integrations Overview](#13-integrations-overview)
14. [Slack Integration — Deep Dive](#14-slack-integration--deep-dive)
15. [Environment Variables](#15-environment-variables)
16. [How to Run Locally](#16-how-to-run-locally)
17. [Production Deploy Notes](#17-production-deploy-notes)
18. [Helper Scripts & Management Commands](#18-helper-scripts--management-commands)
19. [Mental Model for New Developers](#19-mental-model-for-new-developers)
20. [Troubleshooting](#20-troubleshooting)

---

## 1. Product Overview

**VAPTFix** is a vulnerability management / remediation platform.

Typical use case:

1. A company's **Admin** signs up (email OTP / Google / Teams / Slack).
2. The admin fills out **scoping** (company details + testing methodology).
3. The admin invites team members (roles: Patch Management, Network Security, Configuration Management, Architectural Flaws).
4. The admin uploads a **Nessus / PDF / CSV / Excel / HTML** vulnerability report.
5. The backend **parses** the report and stores it in MongoDB.
6. **CrewAI + OpenAI** generate an OS-aware **mitigation card** for each vulnerability and assign it to a team.
7. Team members complete remediation steps, request verification / support / tickets / timeline extensions — either through the website or **directly from Slack/Teams**.
8. The admin tracks progress from the dashboard; there's also a full tabbed mini-dashboard living inside the Slack workspace itself (Home, Register, All Vulns, Team, Support, etc.), so the admin can operate without ever opening the website.

Backend folder path:

```text
vaptfix project/
└── vaptfix/          ← Django backend (the focus of this document)
```

The frontend is separate (`vaptfix.ai`). The backend mostly serves REST APIs, plus its own Block-Kit "mini frontend" for Slack/Teams.

Production backend URL (example): `https://vaptbackend.secureitlab.com`

---

## 2. Tech Stack

| Layer | Technology | Version / Notes |
|-------|------------|-----------------|
| Language | Python 3 | Runs inside a project venv |
| Web framework | **Django** | `3.2.25` |
| API layer | **Django REST Framework** | `3.14.0` |
| Auth | **SimpleJWT** | Access token 1 day, refresh token 30 days |
| Database | **MongoDB** | Atlas / self-hosted |
| Django ↔ Mongo | **Djongo** + **PyMongo** | Djongo ORM + raw queries |
| CORS | `django-cors-headers` | Frontend origin allowlist |
| Static files | **WhiteNoise** | Production static file serving |
| WSGI server | **Gunicorn** | `gthread` workers, `--timeout 300` |
| Email | **SendGrid** | SMTP + API |
| File parsing | pandas, pdfplumber, PyPDF2, openpyxl, BeautifulSoup, defusedxml | Nessus / PDF / Excel |
| AI | **OpenAI + CrewAI + LangChain** | Mitigation cards |
| Chat integrations | **Slack SDK**, Microsoft Graph | Full Block-Kit mini-app inside Slack + a Teams bot |
| Ticketing | Atlassian Jira OAuth API | Issues / projects |
| PDF download | WeasyPrint | Optional |
| Screenshots | **Playwright** (headless Chromium) | Slack dashboard/team/support images |
| Image processing | Pillow | Teams icon upload |
| Config | `python-dotenv` / `python-decouple` | `.env` file |
| Cache | File-based Django cache | `django_cache/` folder |

Dependency file: `vaptfix/requirements.txt`

---

## 3. High-Level Architecture

```text
┌───────────────────────────────┐   ┌───────────────────────────────────────┐
│ Frontend (React/Vite)         │   │ Slack workspace / MS Teams / Jira     │
│ https://vaptfix.ai            │   │ (Block Kit tabs, slash commands,      │
│ Header: Bearer <JWT>          │   │  bot messages, OAuth-linked)          │
└───────────────┬───────────────┘   └───────────────────┬───────────────────┘
                │ HTTPS REST                             │ Slack Events API /
                │                                         │ Interactivity / Graph webhooks
                ▼                                         ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Django + DRF  (vaptfix)                                                │
│  Entry: vaptfix/urls.py                                                 │
│                                                                         │
│  /api/admin/...   → Admin & shared auth + integration APIs              │
│  /api/user/...    → Team member APIs                                    │
│  /api/notifications/ , /api/partners/                                   │
│  /media/...       → Uploaded report files                               │
│  users/*slack*    → Slack OAuth, events, commands, interactivity,       │
│                      dashboard-image (Playwright PNG), status-icon      │
└───────────────┬─────────────────────────┬───────────────────────────────┘
                │                         │
                ▼                         ▼
     ┌──────────────────┐      ┌──────────────────────────┐
     │ Djongo ORM       │      │ Raw PyMongo               │
     │ (identity,       │      │ (reports, cards, fixes,   │
     │  scope, risk,    │      │  tickets, automation,     │
     │  upload meta)    │      │  support requests …)      │
     └────────┬─────────┘      │ Shared pool:               │
              │                │ vaptfix.mongo_client       │
              │                └────────────┬───────────────┘
              └─────────────┬───────────────┘
                            ▼
                   ┌─────────────────┐
                   │  MongoDB        │
                   │  DB name:       │
                   │  vaptfix        │
                   └─────────────────┘

External services:
  SendGrid | Google OAuth | Microsoft Graph (Teams)
  Slack API (Events, Slash Commands, Interactivity, Web API) | Jira (Atlassian) | OpenAI
```

**Request lifecycle (web/API):**

1. Browser/app hits an API with a JWT.
2. `CorsMiddleware` checks the origin.
3. DRF `JWTAuthentication` resolves the user.
4. The view runs its business logic (ORM / pymongo).
5. A JSON response goes back.

**Request lifecycle (Slack):**

1. The user types a slash command, clicks a button/tab, or opens the App Home.
2. Slack sends our backend a signed HTTP POST.
3. The backend acknowledges within 3 seconds with "⏳ Processing…" (a hard Slack requirement).
4. The real work happens in a background thread — the backend calls its own internal APIs (adminregister, automation_scripts_api, etc.) to fetch data.
5. The result is sent back to Slack via `response_url` / `views.update` / `chat.postMessage`.

---

## 4. Project Folder Structure

```text
vaptfix/
│
├── manage.py                 # Django CLI entry point (runserver, migrate, etc.)
├── requirements.txt          # Python dependencies
├── Procfile                  # Gunicorn production start command
├── .env                      # Secrets (do not commit to git)
├── .env.example              # Env template
├── load_scripts_to_db.py     # Automation scripts filesystem → Mongo
├── load_sheet_to_db.py       # Google Sheet CSV → Mongo metadata
│
├── vaptfix/                  # Project settings package
│   ├── settings.py           # Apps, DB, JWT, CORS, OAuth, email
│   ├── urls.py                # Root URL router
│   ├── mongo_client.py       # Shared PyMongo connection + indexes
│   ├── wsgi.py / asgi.py
│
├── users/                    # Auth, User model + Slack/Teams/Jira (BIGGEST app, ~14.5k lines)
│   ├── views.py               # auth (~600 lines) + Teams (~600 lines) + Slack (~11k lines!) + Jira (~1k lines)
│   ├── urls.py
│   └── static/users/icons/   # status-open.png / status-closed.png / status-progress.png (Slack row icons)
├── users_details/            # Team member roster / invites
├── location/                 # Admin locations / sites
├── risk_criteria/             # Admin SLA timelines by severity
├── userrisk_criteria/         # Member view of risk criteria
├── scoping/                  # Pre-upload questionnaire (gate)
├── scope/                    # Pentest scope (IPs/URLs)
├── upload_report/            # Upload, parsers, CrewAI cards
│   ├── parsers.py
│   ├── mitigation_tool.py
│   ├── crew_agent/           # AI agents, tasks, tools
│   └── views.py
├── admindashboard/            # Admin metrics
├── userdashboard/             # Member metrics (team-filtered)
├── adminregister/             # Admin vuln register & fix workflow — also feeds the Slack Register/All-Vulns tabs
├── userregister/              # Member fix workflow
├── adminasset/                # Admin asset hold/delete
├── userasset/                 # Member asset APIs
├── adminmitigationstrategy/   # Cards grouped by team (admin)
├── usermitigationstrategy/    # Same for members
├── notifications/             # In-app notifications + deadline jobs
├── automation_scripts_api/    # Script match / download / feedback — now also does team-inference for the Slack "Script" sub-tab
├── partners/                  # Public partner application form
│
├── automation_scripts/        # Local fix/verify scripts by plugin_id
├── media/                     # Uploaded report files
├── staticfiles/               # collectstatic output
├── django_cache/              # File-based cache
└── docs/                      # Documentation (this file)
```

### Typical Django app internals

Each app usually has these files:

| File | Purpose |
|------|------|
| `models.py` | Djongo models (or empty / unmanaged proxy) |
| `views.py` | API business logic |
| `urls.py` | The app's endpoints |
| `serializers.py` | Request/response validation (DRF) |
| `permissions.py` | Custom permissions (if any) |
| `utils.py` | Helpers (email, Mongo, etc.) |
| `admin.py` | Django admin registration |
| `migrations/` | Schema migrations (Djongo) |

---

## 5. Roles: Admin vs Team Member vs Superadmin

| Role | Identified by | Can do |
|------|----------------|-------------------|
| **Admin** | `User.is_staff = True` | Signup, scoping, upload reports, invite team, dashboards, Slack/Teams/Jira connect, admin-dashboard channel operations in Slack |
| **Team Member** | A `UserDetail` row under an admin; usually `is_staff=False` | View vulns assigned to their team, complete fix steps, request verification, raise support, download automation scripts — via the website or their team's Slack channel |
| **Superadmin** | `User.is_superuser = True` | Upload on behalf of another admin, approve verifications, platform-level ops |

**Team roles** (`UserDetail.Member_role` — a JSON list) map to Slack/Teams channels:

| Member role | Slack channel |
|-------------|-----------------|
| Patch Management | `vaptfix-patch-management-team` |
| Configuration Management | `vaptfix-configuration-management-team` |
| Network Security | `vaptfix-network-security-team` |
| Architectural Flaws | `vaptfix-architectural-flaws-team` |

The admin's own channel is `vaptfix-admin-dashboard` — this is where admin-only slash commands and the tabbed navbar are available (see §14).

`assigned_team` values on AI cards:

- `patch-management`
- `configuration-management`
- `network-security`
- `architectural-flaws`

The member dashboard/register **team filter** works off this same mapping.

---

## 6. Authentication & JWT

### Settings (`vaptfix/settings.py`)

- Default auth: `JWTAuthentication`
- Default permission: `IsAuthenticated` (public endpoints explicitly set `AllowAny`)
- Access token: **1 day**
- Refresh token: **30 days**
- Header format:

```http
Authorization: Bearer <access_token>
```

Refresh endpoint:

```http
POST /api/admin/users/token/refresh/
Body: { "refresh": "<refresh_token>" }
```

Custom user model:

```python
AUTH_USER_MODEL = "users.User"
```

`User` fields (important ones):

- `id` — UUID string primary key
- `email` — unique login
- `login_provider` — `email | google | microsoft_teams | slack | jira`
- Slack / MS / Jira token fields (`slack_bot_token`, `ms_access_token`, `jira_access_token`, etc.)
- `is_staff`, `is_superuser`, `is_active`

### Admin login paths

| Step | Endpoint |
|------|----------|
| Send OTP | `POST /api/admin/users/signup/send-otp/` |
| Verify OTP → JWT | `POST /api/admin/users/signup/verify-otp/` |
| Email login | `POST /api/admin/users/login/` |
| Google | `POST /api/admin/users/google-oauth/` |
| Forgot / reset password | `forgot-password/`, `reset-password/<uid>/<token>/` |

Temporary OTP storage: collection/table `signup_otp_sessions` (`SignupOTPSession` model) — DB-backed (not cache), so it's safe across multiple Gunicorn workers.

### Member login paths

| Endpoint | Notes |
|----------|-------|
| `POST /api/admin/users/user-login/` | Email + password (requires a `UserDetail`) |
| `POST /api/admin/users/slack/member-login/` | Slack identity — checks for cross-platform conflicts |
| `POST /api/admin/users/teams/member-login/` | Teams identity — checks for cross-platform conflicts |
| `GET /api/admin/users/user-login-platform/?email=` | Tells the frontend which platform to use (dispatcher) |

The set-password link arrives by email:

```text
POST /api/admin/users/user-set-password/<uid>/<token>/
```

> Naming note: auth URLs live under `/api/admin/users/` even for team members — this is a historical/legacy structure, not a bug.

---

## 7. Database (MongoDB) — Two Layers

Database name: **`vaptfix`**

Connection env var: `MONGO_DB_URL` (falls back to `MONGO_URI`)

### Layer A — Djongo ORM

Identity, onboarding, scopes, risk SLA, upload file metadata.

| Collection (approx) | Model / App |
|---------------------|-------------|
| `users_user` | `users.User` |
| `signup_otp_sessions` | `SignupOTPSession` |
| `users_details_userdetail` | `users_details.UserDetail` |
| `location_location` | `location.Location` |
| `risk_criteria_riskcriteria` | `risk_criteria.RiskCriteria` |
| `upload_reports` | `upload_report.UploadReport` |
| `scopes`, `scope_entries` | `scope` app |
| `scoping_project_details`, `scoping_testing_methodology` | `scoping` app |
| `notifications_notification` | `notifications.Notification` |

### Layer B — Raw PyMongo (business data)

Report hosts/vulns, AI cards, fix lifecycle, Slack support tickets — **most of the real data lives here**.

Shared helpers:

```python
from vaptfix.mongo_client import MongoContext, get_shared_client, get_shared_db
```

`mongo_client.py` builds a process-wide pooled `MongoClient` and ensures important indexes exist.

| Collection | Purpose |
|------------|---------|
| `nessus_reports` | Parsed Nessus payload + upload metadata |
| `parsed_reports` | Non-Nessus parsed reports |
| `vulnerability_cards` | AI mitigation cards |
| `card_gen_locks` | Concurrent card-generation locks |
| `fix_vulnerabilities` | Open / in-progress fixes |
| `fix_vulnerabilities_closed` | Closed fixes |
| `fix_vulnerability_steps` | Step completion |
| `fix_step_feedback` | Per-step feedback |
| `fix_vulnerability_final_feedback` | Final feedback after close |
| `support_requests` | Support requests (both the website and the Slack Support tab read/write here) |
| `tickets` | Fix-linked tickets |
| `hold_assets`, `deleted_assets` | Soft hold/delete assets |
| `hold_vulnerabilities`, `deleted_vulnerabilities` | Soft hold/delete vulns |
| `timeline_extension_requests` | SLA extension workflow (the Slack Approve/Reject sub-tabs read/write here) |
| `automation_scripts` | Script metadata by `plugin_id` + OS |
| `script_feedback` | Automation script ratings |
| `partners` | Partner form applications |

**Tip for new developers:** if you're looking for vulnerability/fix logic in the code and `models.py` looks empty, check **pymongo collections** and `views.py` instead — that's where the real state actually lives.

---

## 8. End-to-End Business Flow

```text
① Admin signup (OTP / Google / Teams / Slack)
        │
② Scoping complete
   (ProjectDetail + TestingMethodology + submit)
        │
③ Invite team members (users_details)
   + Slack/Teams channels auto-created (ensure_vaptfix_channels / auto_create_vaptfix_team)
        │
④ Upload Nessus / other report
        │
⑤ parsers.dispatch_parse → Mongo (nessus_reports)
        │
⑥ Background CrewAI → vulnerability_cards
   (assigned_team + mitigation steps)
        │
⑦ Admin/member work either on the website OR directly inside Slack:
   - Website: dashboard / register / mitigation strategy pages
   - Slack: /postnavbar → clickable tabs (Home, Register, All Vulns,
     Team, Support, Download) + team-channel slash commands
        │
⑧ Member completes steps (website or /startfix, /manualfix, /autofix in Slack)
   → send-verification
        │
⑨ Superadmin / admin approves (website OR Slack Approve button) → moved to closed collection
        │
⑩ Dashboard metrics + notifications + optional
    tickets / Jira / Slack messages / automation scripts
```

---

## 9. Django Apps — Detail

### 9.1 `users` — Auth & Collaboration Hub (biggest app: ~14.5k lines)

**Path prefix:** `/api/admin/users/`

**What it does:**

- Custom `User` model
- Admin OTP signup / login / logout / profile / password
- Member login / set-password
- Google OAuth
- Microsoft Teams OAuth + team/channel/message APIs + webhooks
- **Slack — full OAuth, Events API, Slash Commands, Interactivity, and a Block-Kit "mini dashboard" inside Slack** (see §14 for the deep-dive — this alone is ~11,000 lines of `views.py`)
- Jira OAuth + full issue/project/comment/transition proxy

Important files: `models.py`, `views.py` (huge — 14,510 lines), `urls.py` (214 lines), `utils.py` (SendGrid mail), `validators.py`, `static/users/icons/` (Slack status icon PNGs)

---

### 9.2 `users_details` — Team Roster

**Prefix:** `/api/admin/users_details/`

**Model:** `UserDetail` — members under an admin (name, email, `Member_role`, Slack/Teams IDs, channel sync fields).

**Key APIs:**

- `POST add-user-detail/` — create a member + send a welcome email (set-password link)
- list / search / update / delete
- `member-profile/`
- `resync-slack/`

When a member is added, both a `User` (with an unusable/set-later password) and a `UserDetail` are usually created.

---

### 9.3 `location`

**Prefix:** `/api/admin/location/`

Admin locations CRUD (`Location` model). The upload flow can sometimes run with `location=None` too (legacy / optional).

---

### 9.4 `scoping` — Upload Gate (Onboarding Forms)

**Prefix:** `/api/admin/scoping/`

| Endpoint | Purpose |
|----------|---------|
| `project-details/` | Company / industry / contacts |
| `testing-methodology/` | Testing type, categories, environment, compliance |
| `submit/` | Mark scoping as submitted |
| `upload-status/` | Card generation ETA / flags |

**Rule:** if scoping isn't complete, report upload can return a **403**.

Models:

- `ProjectDetail` (roughly one per admin)
- `TestingMethodology` (unique per admin + testing_type)

---

### 9.5 `scope` — Technical Scope (IPs / URLs)

**Prefix:** `/api/admin/scope/`

Models:

- `Scope` — name, testing_type (`white_box|grey_box|black_box`), lock fields
- `ScopeEntry` — `internal_ip | external_ip | web_url | mobile_url | subnet`

Endpoints exist for file upload / lock / hierarchy / contact-support.

> `scoping` = questionnaire; `scope` = the actual assets-in-scope list. Similar names, different purposes.

---

### 9.6 `risk_criteria` / `userrisk_criteria`

**Admin:** `/api/admin/risk_criteria/`
**User:** `/api/user/risk_criteria/`

Model `RiskCriteria`: severity-wise SLA strings — `critical`, `high`, `medium`, `low`.

Calendar / week / day views for deadlines; extension-request-related APIs also exist on the dashboard side. The Slack "Timeline Ext." sub-tab (All Vulns tab) displays this same extension request data via Block Kit.

Members interact with their parent admin's criteria through a role-based read/update path — there's no separate duplicate model.

---

### 9.7 `upload_report` — Core Ingestion + AI Cards

**Prefix:** `/api/admin/upload_report/`

**Djongo model:** `UploadReport` (`file`, `file_hash`, `admin`, `member_type`, `status`, `parsed_count`)

**Important endpoints:**

| Path | Purpose |
|------|------|
| `POST upload/` | Multi-file upload + parse + Mongo store |
| `GET upload/all/` | List |
| `GET upload/<report_id>/` | Detail |
| `DELETE upload/<report_id>/delete/` | Delete |
| `POST vulnerability-cards/generate/` | Manual / bulk card generation |
| `POST run-mitigation/` | Run the mitigation pipeline |
| `GET vulnerability-cards/` | List cards |
| `GET vulnerability-cards/<card_id>/` | Card detail |
| `GET latest-report/` | Latest report for the admin |
| `GET report-header/` | Frontend header metadata |
| `GET download-report/` | HTML/PDF (Slack's `/downloadreport` uses similar data) |
| `GET verifications/pending/` | Superadmin queue |
| `POST verifications/approve/` | Approve a verification |

Upload rules (summary):

1. Scoping must be complete.
2. An optional `admin_id` lets a superuser upload on behalf of another admin.
3. `member_type`: `internal` / `external` / `both`.
4. Duplicate `(admin, file_hash)` is rejected.
5. Allowed extensions: `.pdf .csv .xlsx .xls .xml .nessus .html .htm`
6. Nessus → `nessus_reports` + background card generation.
7. Everything else → `parsed_reports`.

---

### 9.8 `admindashboard` / `userdashboard`

Practically no ORM models here — these are **aggregations** over Mongo.

**Admin prefix:** `/api/admin/admindashboard/`
**User prefix:** `/api/user/dashboard/`

Metrics examples:

- total assets, average score, vulnerabilities
- mitigation timeline, mean time to remediate
- vulnerabilities fixed, support requests
- distribution by team, assets by team
- extension request flows (user side)

User APIs are **team-filtered**; admin APIs cover the full org for that admin.

The same underlying dashboard HTML designs (`dashboard.html`, `team.html`, `vulnerability-stats.html`, `support-requests.html`) are reused inside Slack — screenshotted server-side via Playwright and posted as PNG images (§14.7).

---

### 9.9 `adminregister` / `userregister` — Fix Workflow

**Admin:** `/api/admin/adminregister/`
**User:** `/api/user/register/`

Collections: `nessus_reports`, `vulnerability_cards`, `fix_*`, `support_requests`, `tickets`

**Endpoints (from `adminregister/urls.py`):**

| Path | View |
|------|------|
| `register/latest/vulns/` | `LatestSuperAdminVulnerabilityRegisterAPIView` — feeds both the website Register page AND the Slack Register/All-Vulns tabs |
| `report/download-data/`, `report/download/` | Consolidated JSON / self-contained HTML report download |
| `fix-vulnerability/report/<report_id>/asset/<host_name>/create/` | `FixVulnerabilityCreateAPIView` |
| `fix-vulnerability/<fix_vuln_id>/card/` | `FixVulnerabilityCardAPIView` |
| `closed-vulnerabilities/report/<report_id>/asset/<host_name>/` | `ClosedVulnerabilitiesByAssetAPIView` |
| `fix-vulnerability/<fix_vuln_id>/step-complete/` | `FixVulnerabilityStepsAPIView` |
| `fix-vulnerability/<fix_vuln_id>/feedback/` | `FixStepFeedbackAPIView` |
| `fix-vulnerability/<fix_vuln_id>/final-feedback/` | `FixVulnerabilityFinalFeedbackAPIView` (only after closed) |
| `support-requests/raise/report/<report_id>/vulnerability/<vulnerability_id>/` | `RaiseSupportRequestAPIView` |
| `raise-support-requests/vulnerability/<vulnerability_id>/` | `RaiseSupportRequestByVulnerabilityAPIView` |
| `support-requests/report/<report_id>/`, `support-requests/host/<host_name>/` | Support request lookups (also feed the Slack Support tab) |
| `tickets/report/<report_id>/fix/<fix_vulnerability_id>/create/` | `CreateTicketAPIView` |
| `tickets/report/<report_id>/`, `reports/<report_id>/tickets/open|closed/` | Ticket listing |
| `tickets/fix/<fix_vulnerability_id>/ticket/<ticket_id>/` | `TicketDetailAPIView` |
| `fix-vulnerability/<fix_vuln_id>/timeline/` | `VulnerabilityTimelineAPIView` |

Typical flow:

1. Latest vulns list (team-filtered for members)
2. `POST fix-vulnerability/report/<report_id>/asset/<host>/create/`
3. Step completion → `fix_vulnerability_steps`
4. Member requests `send-verification` → review state
5. Superadmin approves → `fix_vulnerabilities_closed`
6. Feedback / tickets / timeline / support

---

### 9.10 `adminasset` / `userasset`

**Admin:** `/api/admin/adminasset/`
**User:** `/api/user/asset/`

Assets come from `nessus_reports.vulnerabilities_by_host`.

Features: list, hold/unhold, delete, per-host vulns, bulk operations by `plugin_name`.

Soft-state collections: `hold_*`, `deleted_*` — respected even after a re-upload.

---

### 9.11 `adminmitigationstrategy` / `usermitigationstrategy`

Groups cards by `assigned_team`; counts assets against each vuln name.

Example cache key: `mitigation_by_team_v2_{admin_id}` (cleared on upload/card generation).

---

### 9.12 `notifications`

**Prefix:** `/api/notifications/`

Model fields: `admin_id`, `recipient_email`, `recipient_type` (`admin|user`), `notif_type`, `title`, `message`, `metadata`, `is_read`.

Example events: deadlines, asset hold/delete, support, extensions, vuln closed.

Also: `deadline_checker.py`, management command `send_deadline_notifications`.

---

### 9.13 `automation_scripts_api`

**Admin:** `/api/admin/automation-scripts/` (`stats/`, `feedback/`, `feedback/<plugin_id>/`, `match/bulk/`, `match/<plugin_id>/`, list)
**User:** `/api/user/automation-scripts/` (`stats/`, `feedback/`, `download/<plugin_id>/`, `match/bulk/`, `match/<plugin_id>/`, list)

Nessus `plugin_id` → matched against a local script DB → download fix/verify script → feedback.

Collections: `automation_scripts`, `script_feedback`

Filesystem scripts: `automation_scripts/<plugin_id>/<OS>/...`

**Recently added:** team-inference logic in `_build_stats()` — when an automation script's team doesn't match anything in `vulnerability_cards` (e.g. a script that came straight from Nessus before card generation ran), a keyword-based fallback (`_infer_team_from_name`, the `_TEAM_KEYWORDS` dict) kicks in so the team is **never left blank**. This matters for the Slack Register tab's "Script" sub-tab stats (`admin_download_stats` → `/stats/`).

---

### 9.14 `partners`

**Prefix:** `/api/partners/`

Public marketing form:

- `GET form-options/`
- `POST apply/` → writes to Mongo `partners` with `status: pending`

No authenticated user is required to apply.

---

## 10. API URL Map

Root file: `vaptfix/urls.py`

| Prefix | App |
|--------|-----|
| `/admin/` | Django admin UI |
| `/api/admin/users/` | users (auth + Teams + Slack + Jira — see below) |
| `/api/admin/location/` | location |
| `/api/admin/users_details/` | users_details |
| `/api/admin/risk_criteria/` | risk_criteria |
| `/api/admin/upload_report/` | upload_report |
| `/api/admin/admindashboard/` | admindashboard |
| `/api/admin/adminregister/` | adminregister |
| `/api/admin/adminasset/` | adminasset |
| `/api/admin/scope/` | scope |
| `/api/admin/scoping/` | scoping |
| `/api/admin/adminmitigationstrategy/` | adminmitigationstrategy |
| `/api/admin/automation-scripts/` | automation_scripts_api (admin) |
| `/api/user/dashboard/` | userdashboard |
| `/api/user/register/` | userregister |
| `/api/user/asset/` | userasset |
| `/api/user/mitigation/` | usermitigationstrategy |
| `/api/user/risk_criteria/` | userrisk_criteria |
| `/api/user/automation-scripts/` | automation_scripts_api (user) |
| `/api/notifications/` | notifications |
| `/api/partners/` | partners |
| `/media/<path>` | serve uploaded reports |

### `users` app URL groups (from `users/urls.py`, all mounted under `/api/admin/users/`)

**Auth / platform login**

```
POST /user-login-platform/
POST /slack/member-login/
POST /teams/member-login/
POST /signup/  /signup/send-otp/  /signup/verify-otp/
POST /login/  /user-login/
POST /google-oauth/
POST /logout/
GET  /profile/
POST /change-password/
POST /forgot-password/  /reset-password/<uid>/<token>/
POST /user-forgot-password/  /user-set-password/<uid>/<token>/
POST /token/refresh/
```

**Microsoft Teams**

```
GET/POST /microsoft-teams/oauth-url/  /microsoft-teams/callback/
POST     /microsoft-teams-oauth/            (login)
POST     /microsoft-teams/token-exchange/   /token-refresh/
POST     /teams/create/  /update/  /delete/  /list/
GET      /teams/channels/list/
POST     /teams/channels/create/  /update/  /delete/  /add-user/
POST     /teams/messages/send/
GET/POST /teams/webhook/                    (Graph subscription validation + member-added events)
POST     /teams/webhook/subscribe/
POST     /teams/sync-members/
```

**Slack** (deep-dive in §14)

```
POST /slack/oauth-url/            GET /slack/callback/
POST /slack/validate-token/       POST /slack/login/     GET /slack-oauth/
GET  /slack/channels/list/        POST /slack/channels/create|update|delete/
POST /slack/messages/send/
POST /slack/channel/join/         POST /slack/channel/add-user/
GET  /slack/users/list/           POST /slack/channel/invite/
POST /slack/events/               GET  /slack/install/
POST /slack/commands/             POST /slack/interactivity/
GET  /slack/dashboard-image/      GET  /slack/status-icon/<kind>/
```

**Jira**

```
GET  /jira/oauth-url/  /jira/callback/
POST /jira/oauth/  /jira/validate-token/  /jira/token/refresh/  /jira/disconnect/
GET  /jira/user/  /jira/resources/
GET  /jira/projects/           POST /jira/projects/create/
GET/POST/DELETE /jira/projects/<project_key>/[update|delete]/
POST /jira/issues/create/  /jira/issues/search/  /jira/issues/comment/
GET/POST/DELETE /jira/issues/<issue_key>/[update|delete|assign]/
GET  /jira/issues/<issue_key>/comments/   POST .../comments/<comment_id>/[update|delete]/
GET  /jira/issues/<issue_key>/transitions/   POST .../transition/
```

The exact path list lives in each app's `urls.py` — that's the reliable place to copy-paste from.

---

## 11. Report Upload & Parsing Pipeline

```text
POST /api/admin/upload_report/upload/
 multipart: files[], member_type, optional admin_id
          │
          ├─ scoping check
          ├─ save file under media/reports/...
          ├─ SHA file_hash (duplicate guard)
          ├─ dispatch_parse(file_path, filename)   ← parsers.py
          ├─ UploadReport ORM row
          ├─ _store_in_mongodb(...)
          │     Nessus → nessus_reports
          │     Other  → parsed_reports
          └─ background thread _auto_generate_cards_bg (Nessus)
```

### `parsers.py` — `dispatch_parse`

| Extension | Function |
|-----------|----------|
| `.pdf` | `parse_pdf` |
| `.csv` | `parse_csv` |
| `.xlsx` / `.xls` | `parse_excel` |
| `.xml` / `.nessus` | `parse_nessus_xml_streaming` (HTML fallback) |
| `.html` / `.htm` | `parse_nessus_html` (full BS4 or lightweight for huge files) |

Typical Nessus JSON shape:

```json
{
  "type": "nessus",
  "scan_info": {},
  "total_hosts": 10,
  "total_vulnerabilities": 120,
  "vulnerabilities_by_host": [
    {
      "host_name": "10.0.0.5",
      "host_information": { "operating-system": "..." },
      "vulnerabilities": [
        {
          "plugin_name": "...",
          "plugin_id": 12345,
          "risk_factor": "Critical",
          "description": "...",
          "plugin_outputs": []
        }
      ]
    }
  ]
}
```

For very large HTML files, time/host/vuln guards and a lightweight regex parser kick in.

---

## 12. AI Mitigation (CrewAI)

### Trigger

1. Automatically after a Nessus upload (background thread)
2. Manually: `POST .../vulnerability-cards/generate/` or `run-mitigation/`

### Tool

`upload_report/mitigation_tool.py` → `MitigationGenerationTool`

Crew: **5 sequential agents** (OpenAI via LangChain `ChatOpenAI`, often defaulting to `gpt-4o-mini`):

| # | Agent | Job |
|---|-------|-----|
| 1 | Vulnerability Analyst | Evidence / severity / CVE understanding |
| 2 | OS Profiler | OS administration profile JSON |
| 3 | Remediation Engineer | OS-correct step-by-step fix |
| 4 | Mitigation Card Formatter & QA | Quality check |
| 5 | Output Structuring Specialist | Final structured JSON |

Code lives under:

```text
upload_report/crew_agent/
  agents.py
  tasks.py
  tools.py
  knowledge_base.py
  os_classifier.py
```

### Output collection: `vulnerability_cards`

Important uniqueness constraint: `(report_id, vulnerability_name, host_name)`

Fields conceptually include:

- `card_id`, mitigation steps / table
- `assigned_team`
- deadlines
- troubleshooting
- OS profile / analysis fields
- cache reuse across similar findings

Flags on the nessus document: `cards_generation_started_at`, `cards_generation_complete`, `cards_generated_count`.

Locks: in-memory + Mongo `card_gen_locks`.

**Required env var:** `OPENAI_API_KEY`

---

## 13. Integrations Overview

### SendGrid (Email)

- OTP, password reset, team invite / set-password emails
- Settings: `SENDGRID_API_KEY`, `DEFAULT_FROM_EMAIL`
- SMTP host: `smtp.sendgrid.net:587`

### Google OAuth

- Admin login: `POST /api/admin/users/google-oauth/`
- Env: `GOOGLE_OAUTH2_CLIENT_ID`, `GOOGLE_OAUTH2_CLIENT_SECRET`

### Microsoft Teams / Graph

- OAuth URL → callback → stores `ms_access_token` / `ms_refresh_token` on the User
- Auto-creates a Team + channels (`auto_create_vaptfix_team`, `_create_vaptfix_channels`); sets a custom team icon via Graph
- Sends messages; adds users; webhooks (a Graph subscription for `member-added` events, which auto-provisions a `UserDetail` + set-password email); manual bulk member sync (`TeamsMemberSyncView`)
- Scopes defined in `settings.MICROSOFT_SCOPES`

### Slack — see §14 for the full deep-dive

Quick summary: install/OAuth, channel CRUD, a full Block-Kit tabbed mini-dashboard (Home/Register/All Vulns/Team/Support/Download), Playwright-rendered PNG dashboard images, event + interactivity + slash-command routing, a public status-icon endpoint. The bot token is stored on the admin's `User.slack_bot_token`.

### Jira (Atlassian)

- OAuth connect / disconnect / refresh
- Projects / issues / comments / assign / transitions proxy
- Tokens: `jira_access_token`, `jira_refresh_token` on the User

### reCAPTCHA

- Used at signup (skipped in DEBUG mode: `RECAPTCHA_SKIP = DEBUG`)
- Env: `RECAPTCHA_SECRET_KEY`

---

## 14. Slack Integration — Deep Dive

This section is new — roughly 80% of `users/views.py` (lines ~3200–14510) belongs to this one feature. The Slack integration has grown into a **full parallel interface** alongside the website: admins/members can view the dashboard, browse the register, start fixes, raise support requests, and approve/reject timeline extensions — all from inside Slack, without ever opening the website.

### 14.1 OAuth install / login / member-login

| Endpoint | Purpose |
|----------|------|
| `GET /slack/install/` | "Add to Slack" marketplace entry point — no VAPTFix login required, redirects straight to Slack's `oauth/v2/authorize` |
| `POST /slack/oauth-url/` | Admin-initiated OAuth URL — binds `admin_id` inside `state` so tokens land on the right admin account; auto-detects ngrok for local dev |
| `GET /slack/callback/` | Exchanges the `code` and saves bot/user tokens; returns an HTML page that `postMessage`s the result back to the frontend popup |
| `POST /slack/login/`, `GET /slack-oauth/` | "Sign in with Slack" (for existing admins) |
| `POST /slack/member-login/` | Non-admin team member login — matches `slack_user_id`/email against `UserDetail`; blocks cross-platform conflicts (if the member is already provisioned for Teams/email, returns a `platform_conflict` error) |

Channel management: list/create/update/delete Slack channels, join a channel, add a user to a channel, list Slack users, invite a user.

`ensure_vaptfix_channels()` auto-creates the workspace's 5 fixed channels: `vaptfix-admin-dashboard` plus the 4 team channels.

### 14.2 "Home tab" — two different things share this name

1. **Static App Home** (`_publish_app_home`, fires on Slack's `app_home_opened` event) — a fixed Block Kit view: a welcome header + a short "what you can do here" blurb + a single "Open VAPTFix Dashboard" button that opens `FRONTEND_URL`. Purely static, no live data.
2. **Live "Home" nav tab** — inside the navbar system, `nav_home` is the default tab. It renders the actual `dashboard.html` design (gauge/donut bento cards) as a **PNG image** (§14.7), not text blocks. The admin posts a persistent navbar in `#vaptfix-admin-dashboard` (`/postnavbar`), and clicking through shows this live dashboard.

### 14.3 Navbar / tab system

`_NAV_ITEMS`: `nav_home`, `nav_fix`, `nav_admin_demo` (All Vulnerabilities), `nav_register`, `nav_team`, `nav_teamperf`, `nav_support`, `nav_download`.

A navbar button click and its equivalent slash command call the **same underlying formatter functions** — so the clickable navbar and the typed commands never drift out of sync.

### 14.4 Register tab

The vulnerability register in Block Kit (not an image — real interactive blocks):

- A severity filter row (All/Critical/High/Medium/Low) + a status filter row (All/Open/Closed/In Progress) — each button carries its own `action_id` (`reg_sev_*`)
- Stable short IDs (`c1`, `h1`, `m1`, `l1`...) are **assigned once over the full unfiltered dataset**, so a clicked row still resolves correctly even after filtering/paging changes what's visible
- 5 rows per page, numbered pagination
- A "Script" sub-tab — automation-script stats (`_format_script_tab`, data source `/api/admin/automation-scripts/stats/`)
- Data source: `/api/admin/adminregister/register/latest/vulns/`

### 14.5 All Vulns tab

Sub-tabs: All Vulns (list), Statistics, Vuln Details, Support, Timeline Ext., Approve, Reject.

- List/Details → the same paginated list as Register, minus the filter UI; clicking a row opens a detail view with a Manual/Automation Fix toggle — **read-only for admins** (no Fix/Run button, mirroring the website's admin-read-only behavior)
- Statistics / Support sub-tabs → rendered as PNG images (the `vulnerability-stats.html` / `support-requests.html` designs)
- Timeline Ext. → extension request data
- Approve / Reject → a list of pending timeline-extension requests with buttons; Reject opens a modal for a rejection reason

### 14.6 Support tab

A support-ticket register inside Slack:

- Status filter (All/Open/Closed) + team filter (All/Patch Mgmt/Config Mgmt/Network Security/Architectural Flaws), 5 rows/page
- Each row has a "View" action → the ticket detail (severity icon, dates)
- A reply capability for admins — a modal opens, and submitting posts the reply back with a visibility choice (internal vs. team-visible)
- Support tickets can also be created from team channels (`/support` command → `_create_support_ticket`) — with file/report links attached, and it notifies the admin channel

### 14.7 Team card & Team Performance

- From a team channel or the `nav_team` navbar item — a "Team Overview" bento-card design rendered as an image (`_build_team_overview_html`, per-team severity breakdown). A wider viewport (840px) is used to keep text crisp in the 2-column team card layout.
- `nav_teamperf` — "Team Performance Monitoring" gets its own separate image (`_build_team_performance_html`).

### 14.8 Dashboard image generation (Playwright)

Block Kit can't render custom CSS / gauges / donuts, so several tabs fall back to server-rendered PNG screenshots:

```text
_dashboard_image_block()
  → builds a short-lived signed token (TimestampSigner, 10-min expiry, carries team_id)
  → returns a Block Kit "image" block pointing at SlackDashboardImageView
        (?token=...&kind=dashboard|team|teamperf|support|supportdetail|stats&t=<cachebust>)

SlackDashboardImageView (GET /slack/dashboard-image/, public/token-gated)
  → unsigns the token to recover team_id
  → fetches data from the relevant backend API
  → builds HTML (_build_dashboard_html / _build_team_overview_html / etc.)
  → calls _dashboard_png_bytes(html, selector)

_dashboard_png_bytes()
  → playwright.sync_api.sync_playwright(), headless Chromium
  → 840×200 viewport, device_scale_factor=2 (retina-sharp text)
  → waits for document.fonts.ready plus a 250ms buffer
  → screenshots a specific CSS selector (.dash / .wrapper) — not the full page
  → returns raw PNG bytes with content-type image/png
```

This endpoint is **public** (no auth headers) because Slack's own servers fetch it directly — security comes from the signed token, not from a JWT.

### 14.9 Slack event / interactivity / slash-command routing

| Endpoint | Purpose |
|----------|---------|
| `POST /slack/events/` (`SlackEventsView`) | Handles `url_verification` (before signature checking), then verifies the HMAC-SHA256 signature (5-minute replay window — verification failure only logs a warning rather than blocking, so channel-invite flows don't break). `event_callback` types go to a background thread's `_handle_event()`, which switches on `event.type`: `channel_created/rename/deleted/archive/unarchive`, `member_joined_channel`, `member_left_channel`, `team_join`, `app_home_opened`, `app_mention` |
| `POST /slack/commands/` (`SlackSlashCommandView`) | Verifies the signature, then branches on `channel_name`: `vaptfix-admin-dashboard` → admin commands (`/teamoverview`, `/vulnstats`, `/dashboard`, `/vulndata`, `/adduser`, `/deleteuser`, `/supportdata`, `/approve`, `/reject`, `/downloadreport`, `/postnavbar`); team channels → member commands (`/viewassigned`, `/startfix`, `/manualfix`, `/autofix`, `/mitigated`, `/retest`, `/support`, `/extend`, `/scriptstats`, `/mitigationstatus`, `/scriptfeedback`). Every request is acknowledged within Slack's 3-second limit; the real work happens in a background thread, and the result is posted back via `response_url` |
| `POST /slack/interactivity/` (`SlackInteractivityView`) | A separate Slack app config surface for Block Kit clicks/modals: `view_submission` (modal submits — add user, delete user, reject reason, support reply), `block_actions` with an open `view` present (live in-modal interactions — checkboxes/pagination), plain `block_actions` (generic button clicks — nav tabs, filters, approve/reject, pagination — parses a pipe-delimited `value` and dispatches through `_handle_action()`) |

**Per-team-member experience** (the equivalent of the admin navbar, but gated by channel name instead of buttons): `/viewassigned` shows the team's assigned vulns/assets in a team channel, alongside `/startfix`, `/manualfix`, `/autofix`, `/mitigated`, `/retest`, `/extend`, `/support`, `/scriptstats`, `/mitigationstatus`, `/scriptfeedback`.

### 14.10 Status icons

`GET /slack/status-icon/<kind>/` — a public, unauthenticated endpoint that serves PNGs from `users/static/users/icons/` (`status-open.png`, `status-closed.png`, `status-progress.png`; `review` also maps to `status-open.png`). It has to be public because Slack's servers fetch `image_url`s directly, with no auth header. Used in the Register/All-Vulns/Support tab rows and the vuln-detail view. There's also an emoji fallback where an inline emoji is cheaper than an image block: ❗ open / 👀 review / 🔄 in-progress / 🔒 closed.

---

## 15. Environment Variables

Template: `.env.example`

| Variable | Purpose |
|----------|---------|
| `SECRET_KEY` | Django secret (**required**) |
| `DEBUG` | `True` / `False` |
| `MONGO_DB_URL` | Mongo connection string |
| `MONGO_URI` | Fallback Mongo URI |
| `OPENAI_API_KEY` | CrewAI / LLM |
| `SENDGRID_API_KEY` | Email |
| `DEFAULT_FROM_EMAIL` | From address |
| `GOOGLE_OAUTH2_CLIENT_ID` / `SECRET` | Google login |
| `MICROSOFT_CLIENT_ID` / `SECRET` / `TENANT_ID` / `REDIRECT_URI` | Teams |
| `SLACK_CLIENT_ID` / `SECRET` / `SIGNING_SECRET` / `REDIRECT_URI` | Slack OAuth + signature verification |
| `JIRA_CLIENT_ID` / `SECRET` / `REDIRECT_URI` | Jira |
| `FRONTEND_URL` | e.g. `https://vaptfix.ai` |
| `VAPTFIX_LOGIN_URL` | Login deep link |
| `BACKEND_BASE_URL` | Public backend URL (the Slack dashboard-image / status-icon public URLs are built from this) |
| `RECAPTCHA_SECRET_KEY` | Bot protection |

`.env` is loaded by `settings.py` (`load_dotenv(override=True)`).

---

## 16. How to Run Locally

### Prerequisites

- Python 3.9+ (per the project's requirements)
- A MongoDB Atlas URI or a local Mongo instance
- (Optional) OpenAI, SendGrid, OAuth credentials, depending on which features you need
- For Slack/Teams testing: ngrok (to expose the local server via a public URL for Slack callbacks)
- For Playwright: `playwright install chromium` (needed to test the Slack dashboard image feature)

### Steps (Windows PowerShell)

```powershell
# 1) Go to the backend folder
cd "d:\secureitlab\vaptfix project\vaptfix project\vaptfix"

# 2) Virtual environment (use the parent venv if one already exists)
..\venv\Scripts\Activate.ps1
# or create a new one:
# python -m venv .venv
# .\.venv\Scripts\Activate.ps1

# 3) Dependencies
pip install -r requirements.txt

# 4) Env file
copy .env.example .env
# make sure SECRET_KEY + MONGO_DB_URL are set in .env
# DEBUG=True for local development

# 5) Migrations (Djongo)
python manage.py migrate

# 6) (Optional) superuser
python manage.py createsuperuser

# 7) Run the server
python manage.py runserver 0.0.0.0:8000
```

Server: `http://127.0.0.1:8000/`

Django admin: `http://127.0.0.1:8000/admin/`

The local frontend usually runs at `http://localhost:5173` — already in the CORS allowlist.

### Quick API test (after admin signup)

```http
POST /api/admin/users/login/
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "YourPassword"
}
```

The response contains `access` + `refresh` tokens — use the Bearer header for all subsequent authenticated calls.

### Static / media

- Uploaded files: `media/`
- With DEBUG=True, Django serves media directly; in production `/media/<path>` is also routed through the custom `serve_report_file`
- Static: `python manage.py collectstatic` → `staticfiles/` + WhiteNoise

---

## 17. Production Deploy Notes

`Procfile`:

```text
web: gunicorn vaptfix.wsgi:application --workers 4 --threads 4 --timeout 300 --worker-class gthread --max-requests 500 --max-requests-jitter 50 --preload
```

Important:

- `DEBUG=False`
- A strong `SECRET_KEY`
- `ALLOWED_HOSTS` / production CORS domains are already configured in settings
- `SECURE_PROXY_SSL_HEADER` for reverse-proxy HTTPS
- Upload memory: max body 50MB
- Card generation is long-running — that's why Gunicorn uses `--timeout 300`
- The Slack dashboard-image endpoint spawns Playwright/Chromium — the production host needs Chromium installed (`playwright install --with-deps chromium`)
- `/slack/interactivity/` also has a debug log (`/tmp/slack_interactivity_debug.log`) — a belt-and-suspenders measure for situations where gunicorn stdout isn't being captured

Example prod backend host: `vaptbackend.secureitlab.com`

---

## 18. Helper Scripts & Management Commands

| Script / Command | Purpose |
|------------------|---------|
| `load_scripts_to_db.py` | Walks `automation_scripts/<plugin_id>/<OS>/` → upserts fix/verify paths into Mongo |
| `load_sheet_to_db.py` | Google Sheet CSV → `automation_scripts` metadata columns |
| `python manage.py send_deadline_notifications` | Deadline notification job (`notifications`) |
| Automation sync (if present) | `sync_automation_scripts` management command |

OS folder mapping (loaders): WIN/WINDOWS → Windows, UBUNTU/LINUX → Linux, CISCO → Cisco, etc.

---

## 19. Mental Model for New Developers

If you're new, read the code in this order:

1. **`vaptfix/settings.py`** — the stack + env
2. **`vaptfix/urls.py`** — the entire API map
3. **`users/models.py` + `users/urls.py`** — who logs in
4. **`scoping/`** — what's mandatory before upload
5. **`upload_report/views.py` + `parsers.py`** — how a report gets in
6. **`upload_report/crew_agent/` + `mitigation_tool.py`** — AI cards
7. **`adminregister/` / `userregister/`** — the fix lifecycle
8. **`admindashboard/` / `userdashboard/`** — metrics
9. **`vaptfix/mongo_client.py`** — the raw Mongo access pattern
10. **`users/views.py` (Slack section, starting around line ~3200)** — only when you're working on a Slack feature; search directly (`Ctrl+F`) for the function name rather than reading the whole file — it's 14.5k lines

Keep in mind:

- **Identity / forms** → mostly Djongo models
- **Vulns / fixes / cards** → mostly raw Mongo collections
- **Admin APIs** → `/api/admin/...`
- **Member APIs** → `/api/user/...` (auth still often lives under `/api/admin/users/...`)
- **Slack "tabs"** → mostly Block Kit (text/buttons), except Home/Team/Team-Performance/Stats/Support-summary, which are **PNG images** (rendered via Playwright)

---

## 20. Troubleshooting

| Problem | Check |
|---------|--------|
| `SECRET_KEY environment variable must be set` | `SECRET_KEY` missing from `.env` |
| Mongo connection / timeout | Is `MONGO_DB_URL` valid? Network / Atlas IP allowlist? |
| 401 Unauthorized | JWT missing/expired → use the refresh token |
| 403 on upload | Was scoping submission completed? Is the user staff? |
| Cards not generating | `OPENAI_API_KEY`, background thread logs, nessus document flags |
| Email not sending | `SENDGRID_API_KEY`, `DEFAULT_FROM_EMAIL` |
| CORS error from frontend | Is the origin in `CORS_ALLOWED_ORIGINS`? |
| Weird Djongo query errors | Avoid complex joins; prefer raw pymongo for heavy queries |
| Large HTML parse slow / timeout | The lightweight parser path; Gunicorn timeout |
| Slack dashboard image blank / erroring | Is Chromium installed? (`playwright install chromium`); has the signed token expired (10 min)? Is the selector `.dash`/`.wrapper` present in the HTML? |
| Slack button click "not responding" | Is the 3-second ack happening? Check background thread exception logs; is `response_url` returning 200/"ok"? |
| Slack signature verification failing | Is `SLACK_SIGNING_SECRET` correct? Clock skew > 5 min? (events verification is non-blocking, so it'll just log a warning, not block) |
| Automation script "team" shows blank | Check the `_infer_team_from_name` keyword fallback — team should never be blank even when there's no `vulnerability_cards` match |

Logs: console logging is enabled; `users` / `users_details` run at DEBUG level.

---

## Appendix A — Key Files Cheat Sheet

| Need | Open this |
|------|-----------|
| Install deps | `requirements.txt` |
| Env template | `.env.example` |
| Settings | `vaptfix/settings.py` |
| Routes | `vaptfix/urls.py` |
| Mongo pool | `vaptfix/mongo_client.py` |
| User model | `users/models.py` |
| Auth routes | `users/urls.py` |
| Upload + AI | `upload_report/` |
| Parsers | `upload_report/parsers.py` |
| CrewAI agents | `upload_report/crew_agent/` |
| Slack Block Kit tabs / events / interactivity | `users/views.py` (search by function name, ~line 3200 onwards) |
| Slack status icons | `users/static/users/icons/` |
| Prod start | `Procfile` |

---

## Appendix B — Sample Collection Relationships

```text
users_user (Admin)
    │
    ├── users_details_userdetail (Members + roles)
    ├── scoping_* (must complete before upload)
    ├── scopes / scope_entries (technical scope)
    ├── risk_criteria_riskcriteria (SLA)
    ├── upload_reports (file meta)
    │
    └── nessus_reports (parsed data)
            │
            ├── vulnerability_cards (AI output, assigned_team)
            │         │
            │         └── automation_scripts (by plugin_id)
            │
            ├── fix_vulnerabilities ──► steps / feedback / tickets
            │         │
            │         └── (after approve) fix_vulnerabilities_closed
            │
            ├── hold_* / deleted_*
            ├── support_requests ◄── also written/read from the Slack Support tab
            └── timeline_extension_requests ◄── also approved/rejected from the Slack All-Vulns tab

notifications_notification ← events across the above
partners ← public applications (independent)
```

---

*Document generated for VAPTFix backend onboarding. Keep the relevant sections of this document updated after code changes — especially §14 (Slack), which is still the most actively developed area.*
