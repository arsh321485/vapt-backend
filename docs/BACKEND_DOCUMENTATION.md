# VAPTFix Backend — Complete Documentation

Yeh document VAPTFix backend ka **complete guide** hai. Agar aapko pehle se VAPTFix code ki koi knowledge nahi hai, to is document se samajh aa jayega:

- Project kya hai aur kaise kaam karta hai  
- Kaunsi technology use hoti hai  
- Folder / app structure kahan kya hai  
- Request flow, auth, database  
- Har Django app ka role  
- Local machine par kaise run karein  

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
13. [Integrations](#13-integrations)  
14. [Environment Variables](#14-environment-variables)  
15. [How to Run Locally](#15-how-to-run-locally)  
16. [Production Deploy Notes](#16-production-deploy-notes)  
17. [Helper Scripts & Management Commands](#17-helper-scripts--management-commands)  
18. [Mental Model for New Developers](#18-mental-model-for-new-developers)  
19. [Troubleshooting](#19-troubleshooting)  

---

## 1. Product Overview

**VAPTFix** ek vulnerability management / remediation platform hai.

Typical use-case:

1. Company ka **Admin** signup karta hai.  
2. Admin **scoping** (company + testing methodology) fill karta hai.  
3. Admin team members invite karta hai (roles: Patch Management, Network Security, Configuration Management, Architectural Flaws).  
4. Admin **Nessus / PDF / CSV / Excel / HTML** vulnerability report upload karta hai.  
5. Backend report **parse** karta hai aur MongoDB mein store karta hai.  
6. **CrewAI + OpenAI** se har vulnerability ke liye OS-aware **mitigation card** banata hai aur team assign karta hai.  
7. Team members steps complete karte hain, verification / support / tickets / timeline extension request karte hain.  
8. Admin dashboard se progress dekhta hai; Slack / Teams / Jira se bhi collaborate ho sakta hai.

Backend folder path:

```text
vaptfix project/
└── vaptfix/          ← Django backend (yahi document ka focus)
```

Frontend alag hai (`vaptfix.ai`). Backend mostly REST APIs serve karta hai.

Production backend URL (example): `https://vaptbackend.secureitlab.com`

---

## 2. Tech Stack

| Layer | Technology | Version / Notes |
|-------|------------|-----------------|
| Language | Python 3 | Project venv ke saath |
| Web framework | **Django** | `3.2.25` |
| API layer | **Django REST Framework** | `3.14.0` |
| Auth | **SimpleJWT** | Access 1 day, Refresh 30 days |
| Database | **MongoDB** | Atlas / self-hosted |
| Django ↔ Mongo | **Djongo** + **PyMongo** | Djongo ORM + raw queries |
| CORS | `django-cors-headers` | Frontend origins allowlist |
| Static files | **WhiteNoise** | Production static serving |
| WSGI server | **Gunicorn** | `gthread` workers |
| Email | **SendGrid** | SMTP + API |
| File parsing | pandas, pdfplumber, PyPDF2, openpyxl, BeautifulSoup, defusedxml | Nessus / PDF / Excel |
| AI | **OpenAI + CrewAI + LangChain** | Mitigation cards |
| Chat integrations | Slack SDK, Microsoft Graph | Channels + bots |
| Ticketing | Atlassian Jira OAuth API | Issues / projects |
| PDF download | WeasyPrint | Optional |
| Screenshots (Slack) | Playwright | Dashboard image |
| Config | `python-dotenv` / `python-decouple` | `.env` file |
| Cache | File-based Django cache | `django_cache/` folder |

Dependencies file: `vaptfix/requirements.txt`

---

## 3. High-Level Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│  Frontend (React / Vite) — https://vaptfix.ai              │
│  Header: Authorization: Bearer <JWT access token>           │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTPS REST
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Django + DRF  (vaptfix)                                    │
│  Entry: vaptfix/urls.py                                     │
│                                                             │
│  /api/admin/...   → Admin & shared auth APIs                │
│  /api/user/...    → Team member APIs                        │
│  /api/notifications/                                        │
│  /api/partners/                                             │
│  /media/...       → Uploaded report files                   │
└───────────────┬─────────────────────────┬───────────────────┘
                │                         │
                ▼                         ▼
     ┌──────────────────┐      ┌──────────────────────────┐
     │ Djongo ORM       │      │ Raw PyMongo              │
     │ (identity,       │      │ (reports, cards, fixes,  │
     │  scope, risk,    │      │  tickets, automation…)   │
     │  upload meta)    │      │ Shared pool:             │
     └────────┬─────────┘      │ vaptfix.mongo_client    │
              │                └────────────┬─────────────┘
              └─────────────┬───────────────┘
                            ▼
                   ┌─────────────────┐
                   │  MongoDB        │
                   │  DB name:       │
                   │  vaptfix        │
                   └─────────────────┘

External services:
  SendGrid | Google OAuth | Microsoft Graph (Teams)
  Slack API | Jira (Atlassian) | OpenAI
```

**Request lifecycle (simple):**

1. Browser/app JWT ke saath API hit karti hai.  
2. `CorsMiddleware` origin check karta hai.  
3. DRF `JWTAuthentication` user nikalta hai.  
4. View business logic chalti hai (ORM / pymongo).  
5. JSON response wapas.

---

## 4. Project Folder Structure

```text
vaptfix/
│
├── manage.py                 # Django CLI entry (runserver, migrate, etc.)
├── requirements.txt          # Python dependencies
├── Procfile                  # Gunicorn production start command
├── .env                      # Secrets (git mein commit mat karo)
├── .env.example              # Env template
├── load_scripts_to_db.py     # Automation scripts filesystem → Mongo
├── load_sheet_to_db.py       # Google Sheet CSV → Mongo metadata
│
├── vaptfix/                  # Project settings package
│   ├── settings.py           # Apps, DB, JWT, CORS, OAuth, email
│   ├── urls.py               # Root URL router
│   ├── mongo_client.py       # Shared PyMongo connection + indexes
│   ├── wsgi.py / asgi.py
│
├── users/                    # Auth, User model, Slack/Teams/Jira
├── users_details/            # Team member roster / invites
├── location/                 # Admin locations / sites
├── risk_criteria/            # Admin SLA timelines by severity
├── userrisk_criteria/        # Member view of risk criteria
├── scoping/                  # Pre-upload questionnaire (gate)
├── scope/                    # Pentest scope (IPs/URLs)
├── upload_report/            # Upload, parsers, CrewAI cards
│   ├── parsers.py
│   ├── mitigation_tool.py
│   ├── crew_agent/           # AI agents, tasks, tools
│   └── views.py
├── admindashboard/           # Admin metrics
├── userdashboard/            # Member metrics (team-filtered)
├── adminregister/            # Admin vuln register & fix workflow
├── userregister/             # Member fix workflow
├── adminasset/               # Admin asset hold/delete
├── userasset/                # Member asset APIs
├── adminmitigationstrategy/  # Cards grouped by team (admin)
├── usermitigationstrategy/   # Same for members
├── notifications/            # In-app notifications + deadline jobs
├── automation_scripts_api/   # Script match / download / feedback
├── partners/                 # Public partner application form
│
├── automation_scripts/       # Local fix/verify scripts by plugin_id
├── media/                    # Uploaded report files
├── staticfiles/              # collectstatic output
├── django_cache/             # File-based cache
└── docs/                     # Documentation (yeh file)
```

### Typical Django app internals

Har app mein usually ye files hoti hain:

| File | Kaam |
|------|------|
| `models.py` | Djongo models (ya empty / unmanaged proxy) |
| `views.py` | API business logic |
| `urls.py` | App ke endpoints |
| `serializers.py` | Request/response validation (DRF) |
| `permissions.py` | Custom permission (agar hai) |
| `utils.py` | Helpers (email, Mongo, etc.) |
| `admin.py` | Django admin registration |
| `migrations/` | Schema migrations (Djongo) |

---

## 5. Roles: Admin vs Team Member vs Superadmin

| Role | Kaise identify | Kya kar sakta hai |
|------|----------------|-------------------|
| **Admin** | `User.is_staff = True` | Signup, scoping, upload reports, invite team, dashboards, Slack/Teams/Jira connect |
| **Team Member** | `UserDetail` row under kisi admin ke; usually `is_staff=False` | Assigned team vulns dekhna, fix steps, verification request, support, automation download |
| **Superadmin** | `User.is_superuser = True` | Doosre admin ke liye upload, verification approve, platform-level ops |

**Team roles** (`UserDetail.Member_role` — JSON list), Slack/Teams channels se map:

| Member role | Typical channel |
|-------------|-----------------|
| Patch Management | `vaptfix-*-patch` style channels |
| Configuration Management | config team channel |
| Network Security | network team channel |
| Architectural Flaws | architectural team channel |

AI cards par `assigned_team` values:

- `patch-management`
- `configuration-management`
- `network-security`
- `architectural-flaws`

Member dashboard / register **team filter** isi mapping se kaam karta hai.

---

## 6. Authentication & JWT

### Settings (`vaptfix/settings.py`)

- Default auth: `JWTAuthentication`
- Default permission: `IsAuthenticated` (public endpoints `AllowAny` set karte hain)
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

`User` fields (important):

- `id` — UUID string primary key  
- `email` — unique login  
- `login_provider` — `email | google | microsoft_teams | slack | jira`  
- Slack / MS / Jira token fields  
- `is_staff`, `is_superuser`, `is_active`

### Admin login paths

| Step | Endpoint |
|------|----------|
| Send OTP | `POST /api/admin/users/signup/send-otp/` |
| Verify OTP → JWT | `POST /api/admin/users/signup/verify-otp/` |
| Email login | `POST /api/admin/users/login/` |
| Google | `POST /api/admin/users/google-oauth/` |
| Forgot / reset password | `forgot-password/`, `reset-password/<uid>/<token>/` |

OTP temporary store: collection/table `signup_otp_sessions` (`SignupOTPSession` model) — multi-worker safe (cache nahi).

### Member login paths

| Endpoint | Notes |
|----------|-------|
| `POST /api/admin/users/user-login/` | Email + password (UserDetail required) |
| `POST /api/admin/users/slack/member-login/` | Slack identity |
| `POST /api/admin/users/teams/member-login/` | Teams identity |
| `GET /api/admin/users/user-login-platform/?email=` | Kaunsa platform use karna hai |

Set password link email se aata hai:

```text
POST /api/admin/users/user-set-password/<uid>/<token>/
```

> Naming note: Auth URLs `/api/admin/users/` ke under hain even for members — historical structure hai.

---

## 7. Database (MongoDB) — Two Layers

Database name: **`vaptfix`**

Connection env: `MONGO_DB_URL` (fallback `MONGO_URI`)

### Layer A — Djongo ORM

Identity, onboarding, scopes, risk SLA, upload file metadata.

Examples:

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

Report hosts/vulns, AI cards, fix lifecycle — **zyadatar yahan**.

Shared helpers:

```python
from vaptfix.mongo_client import MongoContext, get_shared_client, get_shared_db
```

`mongo_client.py` ek process-wide pooled `MongoClient` banata hai aur important indexes ensure karta hai.

| Collection | Purpose |
|------------|---------|
| `nessus_reports` | Parsed Nessus payload + upload meta |
| `parsed_reports` | Non-Nessus parsed reports |
| `vulnerability_cards` | AI mitigation cards |
| `card_gen_locks` | Concurrent card-generation locks |
| `fix_vulnerabilities` | Open / in-progress fixes |
| `fix_vulnerabilities_closed` | Closed fixes |
| `fix_vulnerability_steps` | Step completion |
| `fix_step_feedback` | Per-step feedback |
| `fix_vulnerability_final_feedback` | Final feedback after close |
| `support_requests` | Support requests |
| `tickets` | Fix-linked tickets |
| `hold_assets`, `deleted_assets` | Soft hold/delete assets |
| `hold_vulnerabilities`, `deleted_vulnerabilities` | Soft hold/delete vulns |
| `timeline_extension_requests` | SLA extension workflow |
| `automation_scripts` | Script metadata by `plugin_id` + OS |
| `script_feedback` | Automation script ratings |
| `partners` | Partner form applications |

**New developer tip:** Agar code mein vulnerability / fix logic dhundh rahe ho aur `models.py` khali dikhe, to **pymongo collections** aur `views.py` dekho — wahi real state hai.

---

## 8. End-to-End Business Flow

```text
① Admin signup (OTP / Google / Teams / Slack)
        │
② Scoping complete
   (ProjectDetail + TestingMethodology + submit)
        │
③ Invite team members (users_details)
   + optional Slack / Teams channels
        │
④ Upload Nessus / other report
        │
⑤ parsers.dispatch_parse → Mongo (nessus_reports)
        │
⑥ Background CrewAI → vulnerability_cards
   (assigned_team + mitigation steps)
        │
⑦ Member dashboard / register → Fix create
        │
⑧ Complete steps → send verification
        │
⑨ Superadmin approve → closed collection
        │
⑩ Dashboard metrics + notifications + optional
    tickets / Jira / Slack messages / automation scripts
```

---

## 9. Django Apps — Detail

### 9.1 `users` — Auth & Collaboration Hub

**Path prefix:** `/api/admin/users/`

**Kaam:**

- Custom `User` model  
- Admin OTP signup / login / logout / profile / password  
- Member login / set-password  
- Google OAuth  
- Microsoft Teams OAuth + team/channel/message APIs + webhooks  
- Slack OAuth + channels + slash commands + interactivity + dashboard image  
- Jira OAuth + full issue/project/comment/transition proxy  

Important files: `models.py`, `views.py` (bahut bada), `urls.py`, `utils.py` (SendGrid mail), `validators.py`

---

### 9.2 `users_details` — Team Roster

**Prefix:** `/api/admin/users_details/`

**Model:** `UserDetail` — admin ke under members (name, email, `Member_role`, Slack/Teams IDs, channel sync fields).

**Key APIs:**

- `POST add-user-detail/` — member create + welcome email (set-password link)  
- list / search / update / delete  
- `member-profile/`  
- `resync-slack/`  

Jab member add hota hai, aksar ek `User` (unusable/setlater password) + `UserDetail` dono banate hain.

---

### 9.3 `location`

**Prefix:** `/api/admin/location/`

Admin locations CRUD (`Location` model). Upload flow mein kabhi-kabhi `location=None` bhi chal sakta hai (legacy / optional).

---

### 9.4 `scoping` — Upload Gate (Onboarding Forms)

**Prefix:** `/api/admin/scoping/`

| Endpoint | Purpose |
|----------|---------|
| `project-details/` | Company / industry / contacts |
| `testing-methodology/` | Testing type, categories, environment, compliance |
| `submit/` | Mark scoping submitted |
| `upload-status/` | Card generation ETA / flags |

**Rule:** Scoping complete na ho to report upload **403** de sakta hai.

Models:

- `ProjectDetail` (approx one per admin)  
- `TestingMethodology` (unique per admin + testing_type)

---

### 9.5 `scope` — Technical Scope (IPs / URLs)

**Prefix:** `/api/admin/scope/`

Models:

- `Scope` — name, testing_type (`white_box|grey_box|black_box`), lock fields  
- `ScopeEntry` — `internal_ip | external_ip | web_url | mobile_url | subnet`

File upload / lock / hierarchy / contact-support endpoints available.

> `scoping` = questionnaire; `scope` = actual assets-in-scope list. Naam similar, purpose alag.

---

### 9.6 `risk_criteria` / `userrisk_criteria`

**Admin:** `/api/admin/risk_criteria/`  
**User:** `/api/user/risk_criteria/`

Model `RiskCriteria`: severity-wise SLA strings — `critical`, `high`, `medium`, `low`.

Calendar / week / day views for deadlines; extension requests se related APIs dashboard side par bhi hain.

Members parent admin ke criteria padhte/update path se interact karte hain (alag duplicate model nahi — role based access).

---

### 9.7 `upload_report` — Core Ingestion + AI Cards

**Prefix:** `/api/admin/upload_report/`

**Djongo model:** `UploadReport` (`file`, `file_hash`, `admin`, `member_type`, `status`, `parsed_count`)

**Important endpoints:**

| Path | Kaam |
|------|------|
| `POST upload/` | Multi-file upload + parse + Mongo store |
| `GET upload/all/` | List |
| `GET upload/<report_id>/` | Detail |
| `DELETE upload/<report_id>/delete/` | Delete |
| `POST vulnerability-cards/generate/` | Manual / bulk card generation |
| `POST run-mitigation/` | Run mitigation pipeline |
| `GET vulnerability-cards/` | List cards |
| `GET vulnerability-cards/<card_id>/` | Card detail |
| `GET latest-report/` | Latest report for admin |
| `GET report-header/` | Frontend header meta |
| `GET download-report/` | HTML/PDF |
| `GET verifications/pending/` | Superadmin queue |
| `POST verifications/approve/` | Approve verification |

Upload rules (summary):

1. Scoping must be complete.  
2. Superuser optional `admin_id` se kisi admin ke naam pe upload.  
3. `member_type`: `internal` / `external` / `both`.  
4. Duplicate `(admin, file_hash)` reject.  
5. Allowed extensions: `.pdf .csv .xlsx .xls .xml .nessus .html .htm`  
6. Nessus → `nessus_reports` + background card generation.  
7. Other → `parsed_reports`.

---

### 9.8 `admindashboard` / `userdashboard`

ORM models practically nahi — **aggregations** over Mongo.

**Admin prefix:** `/api/admin/admindashboard/`  
**User prefix:** `/api/user/dashboard/`

Metrics examples:

- total assets, avg score, vulnerabilities  
- mitigation timeline, mean time to remediate  
- vulnerabilities fixed, support requests  
- distribution by team, assets by team  
- extension request flows (user side)

User APIs **team-filtered**; admin APIs full org for that admin.

---

### 9.9 `adminregister` / `userregister` — Fix Workflow

**Admin:** `/api/admin/adminregister/`  
**User:** `/api/user/register/`

Collections: `nessus_reports`, `vulnerability_cards`, `fix_*`, `support_requests`, `tickets`

Typical flow:

1. Latest vulns list (user = team filter)  
2. `POST fix-vulnerability/report/<report_id>/asset/<host>/create/`  
3. Step complete → `fix_vulnerability_steps`  
4. Member `send-verification` → review state  
5. Superadmin approve → `fix_vulnerabilities_closed`  
6. Feedback / tickets / timeline / support

---

### 9.10 `adminasset` / `userasset`

**Admin:** `/api/admin/adminasset/`  
**User:** `/api/user/asset/`

Assets `nessus_reports.vulnerabilities_by_host` se aate hain.

Features: list, hold/unhold, delete, per-host vulns, bulk by `plugin_name`.

Soft-state collections: `hold_*`, `deleted_*` — re-upload ke baad bhi respect.

---

### 9.11 `adminmitigationstrategy` / `usermitigationstrategy`

Cards ko `assigned_team` se group; vuln-name ke against asset counts.

Cache key example: `mitigation_by_team_v2_{admin_id}` (upload/card gen pe clear).

---

### 9.12 `notifications`

**Prefix:** `/api/notifications/`

Model fields: `admin_id`, `recipient_email`, `recipient_type` (`admin|user`), `notif_type`, `title`, `message`, `metadata`, `is_read`.

Events examples: deadlines, asset hold/delete, support, extensions, vuln closed.

Also: `deadline_checker.py`, management command `send_deadline_notifications`.

---

### 9.13 `automation_scripts_api`

**Admin:** `/api/admin/automation-scripts/`  
**User:** `/api/user/automation-scripts/`

Nessus `plugin_id` → local/script DB match → download fix/verify script → feedback.

Collections: `automation_scripts`, `script_feedback`

Filesystem scripts: `automation_scripts/<plugin_id>/<OS>/...`

---

### 9.14 `partners`

**Prefix:** `/api/partners/`

Public marketing form:

- `GET form-options/`  
- `POST apply/` → Mongo `partners` with `status: pending`

No authenticated user required for apply.

---

## 10. API URL Map

Root file: `vaptfix/urls.py`

| Prefix | App |
|--------|-----|
| `/admin/` | Django admin UI |
| `/api/admin/users/` | users |
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

Exact path list har app ke `urls.py` mein hai — wahan se copy-paste reliable hai.

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

Large HTML files ke liye time/host/vuln guards aur lightweight regex parser use hota hai.

---

## 12. AI Mitigation (CrewAI)

### Trigger

1. Automatic after Nessus upload (background thread)  
2. Manual: `POST .../vulnerability-cards/generate/` or `run-mitigation/`

### Tool

`upload_report/mitigation_tool.py` → `MitigationGenerationTool`

Crew: **5 sequential agents** (OpenAI via LangChain `ChatOpenAI`, default often `gpt-4o-mini`):

| # | Agent | Job |
|---|-------|-----|
| 1 | Vulnerability Analyst | Evidence / severity / CVE understanding |
| 2 | OS Profiler | OS administration profile JSON |
| 3 | Remediation Engineer | OS-correct step-by-step fix |
| 4 | Mitigation Card Formatter & QA | Quality check |
| 5 | Output Structuring Specialist | Final structured JSON |

Code under:

```text
upload_report/crew_agent/
  agents.py
  tasks.py
  tools.py
  knowledge_base.py
  os_classifier.py
```

### Output collection: `vulnerability_cards`

Important uniqueness: `(report_id, vulnerability_name, host_name)`

Fields conceptually include:

- `card_id`, mitigation steps / table  
- `assigned_team`  
- deadlines  
- troubleshooting  
- OS profile / analysis fields  
- cache reuse across similar findings  

Flags on nessus doc: `cards_generation_started_at`, `cards_generation_complete`, `cards_generated_count`.

Locks: in-memory + Mongo `card_gen_locks`.

**Env required:** `OPENAI_API_KEY`

---

## 13. Integrations

### SendGrid (Email)

- OTP, password reset, team invite / set-password emails  
- Settings: `SENDGRID_API_KEY`, `DEFAULT_FROM_EMAIL`  
- SMTP host: `smtp.sendgrid.net:587`

### Google OAuth

- Admin login: `POST /api/admin/users/google-oauth/`  
- Env: `GOOGLE_OAUTH2_CLIENT_ID`, `GOOGLE_OAUTH2_CLIENT_SECRET`

### Microsoft Teams / Graph

- OAuth URL → callback → store `ms_access_token` / `ms_refresh_token` on User  
- Auto create Team + channels; send messages; add users; webhooks; member sync  
- Scopes defined in `settings.MICROSOFT_SCOPES`

### Slack

- Install / OAuth / login / member-login  
- Channel CRUD, invite by role, events, slash commands, interactivity  
- Dashboard image endpoint (Playwright)  
- Bot token stored on admin User (`slack_bot_token`)

### Jira (Atlassian)

- OAuth connect / disconnect / refresh  
- Projects / issues / comments / assign / transitions proxy  
- Tokens: `jira_access_token`, `jira_refresh_token` on User

### reCAPTCHA

- Signup pe use (DEBUG mode mein skip: `RECAPTCHA_SKIP = DEBUG`)  
- Env: `RECAPTCHA_SECRET_KEY`

---

## 14. Environment Variables

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
| `SLACK_CLIENT_ID` / `SECRET` / `SIGNING_SECRET` / `REDIRECT_URI` | Slack |
| `JIRA_CLIENT_ID` / `SECRET` / `REDIRECT_URI` | Jira |
| `FRONTEND_URL` | e.g. `https://vaptfix.ai` |
| `VAPTFIX_LOGIN_URL` | Login deep link |
| `BACKEND_BASE_URL` | Public backend URL |
| `RECAPTCHA_SECRET_KEY` | Bot protection |

`.env` file `settings.py` load karti hai (`load_dotenv(override=True)`).

---

## 15. How to Run Locally

### Prerequisites

- Python 3.9+ (project ke hisaab se)  
- MongoDB Atlas URI ya local Mongo  
- (Optional) OpenAI, SendGrid, OAuth credentials jaisi features chahiye

### Steps (Windows PowerShell)

```powershell
# 1) Backend folder mein jao
cd "d:\secureitlab\vaptfix project\vaptfix project\vaptfix"

# 2) Virtual environment (agar pehle se parent venv hai wo use kar sakte ho)
# Project root par venv/ dikhta hai — activate:
..\venv\Scripts\Activate.ps1
# ya naya banao:
# python -m venv .venv
# .\.venv\Scripts\Activate.ps1

# 3) Dependencies
pip install -r requirements.txt

# 4) Env file
copy .env.example .env
# .env mein SECRET_KEY + MONGO_DB_URL zaroor set karo
# DEBUG=True local ke liye

# 5) Migrations (Djongo)
python manage.py migrate

# 6) (Optional) superuser
python manage.py createsuperuser

# 7) Run server
python manage.py runserver 0.0.0.0:8000
```

Server: `http://127.0.0.1:8000/`

Django admin: `http://127.0.0.1:8000/admin/`

Frontend local usually `http://localhost:5173` — CORS allowlist mein already hai.

### Quick API test (after admin signup)

```http
POST /api/admin/users/login/
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "YourPassword"
}
```

Response mein `access` + `refresh` tokens milenge — baaki authenticated calls pe Bearer header lagao.

### Static / media

- Uploaded files: `media/`  
- DEBUG=True pe Django media serve; production mein `/media/<path>` custom `serve_report_file` se bhi route hai  
- Static: `python manage.py collectstatic` → `staticfiles/` + WhiteNoise

---

## 16. Production Deploy Notes

`Procfile`:

```text
web: gunicorn vaptfix.wsgi:application --workers 4 --threads 4 --timeout 300 --worker-class gthread --max-requests 500 --max-requests-jitter 50 --preload
```

Important:

- `DEBUG=False`  
- Strong `SECRET_KEY`  
- `ALLOWED_HOSTS` / CORS production domains already settings mein configured  
- `SECURE_PROXY_SSL_HEADER` reverse-proxy HTTPS ke liye  
- Upload memory: max body 50MB  
- Card generation long-running — Gunicorn `--timeout 300` isliye  

Prod backend host example: `vaptbackend.secureitlab.com`

---

## 17. Helper Scripts & Management Commands

| Script / Command | Purpose |
|------------------|---------|
| `load_scripts_to_db.py` | `automation_scripts/<plugin_id>/<OS>/` walk → Mongo upsert fix/verify paths |
| `load_sheet_to_db.py` | Google Sheet CSV → `automation_scripts` metadata columns |
| `python manage.py send_deadline_notifications` | Deadline notification job (`notifications`) |
| Sync automation (agar present) | `sync_automation_scripts` management command |

OS folder mapping (loaders): WIN/WINDOWS → Windows, UBUNTU/LINUX → Linux, CISCO → Cisco, etc.

---

## 18. Mental Model for New Developers

Agar aap naye ho, yeh order mein code padho:

1. **`vaptfix/settings.py`** — stack + env  
2. **`vaptfix/urls.py`** — poora API map  
3. **`users/models.py` + `users/urls.py`** — kaun login karta hai  
4. **`scoping/`** — upload se pehle kya mandatory hai  
5. **`upload_report/views.py` + `parsers.py`** — report kaise andar aati hai  
6. **`upload_report/crew_agent/` + `mitigation_tool.py`** — AI cards  
7. **`adminregister/` / `userregister/`** — fix lifecycle  
8. **`admindashboard/` / `userdashboard/`** — metrics  
9. **`vaptfix/mongo_client.py`** — raw Mongo access pattern  

Yaad rakho:

- **Identity / forms** → mostly Djongo models  
- **Vulns / fixes / cards** → mostly raw Mongo collections  
- **Admin APIs** → `/api/admin/...`  
- **Member APIs** → `/api/user/...` (auth still often `/api/admin/users/...`)

---

## 19. Troubleshooting

| Problem | Check |
|---------|--------|
| `SECRET_KEY environment variable must be set` | `.env` mein `SECRET_KEY` missing |
| Mongo connection / timeout | `MONGO_DB_URL` valid? Network / Atlas IP allowlist? |
| 401 Unauthorized | JWT missing/expired → refresh token use karo |
| 403 on upload | Scoping submit complete kiya? Staff user? |
| Cards generate nahi ho rahe | `OPENAI_API_KEY`, background thread logs, nessus doc flags |
| Email nahi ja raha | `SENDGRID_API_KEY`, `DEFAULT_FROM_EMAIL` |
| CORS error frontend se | Origin `CORS_ALLOWED_ORIGINS` mein hai? |
| Djongo weird query errors | Complex joins avoid; raw pymongo prefer for heavy queries |
| Large HTML parse slow / timeout | Lightweight parser path; Gunicorn timeout |

Logs: console logging enabled; `users` / `users_details` DEBUG level.

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
            ├── support_requests
            └── timeline_extension_requests

notifications_notification ← events across above
partners ← public applications (independent)
```

---

*Document generated for VAPTFix backend onboarding. Code change ke baad is document ke relevant sections update rakhna useful hai.*
