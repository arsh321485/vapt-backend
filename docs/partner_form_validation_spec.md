# Partner Application Form — Frontend Validation Spec

For the frontend developer building the `/partner` page. This mirrors the
validation now enforced by the backend (`partners/serializers.py`), so
client-side checks and server error messages match exactly.

## Endpoint

```
POST /api/partners/apply/
Content-Type: application/json
```

- **Success → 201**
  ```json
  { "message": "Partner application submitted successfully", "id": "..." }
  ```
- **Validation failure → 400**
  ```json
  { "<field_name>": ["<error message>"], "<field_name_2>": ["<error message>"] }
  ```
  Response is a JSON object keyed by the exact field name below. Map each
  key to its form field and show the message under it in red. Multiple
  fields can fail at once — show all of them, not just the first.

Dropdown options (`country`, `company_size`, `partner_type`, `phone_country_codes`) come from
`GET /api/partners/form-options/`. `phone_country_codes` is a list of
`{"country": "India", "code": "+91"}` objects (all 195 countries) — render it
as a searchable dropdown next to the phone number input, e.g. "India (+91)",
and submit just the `code` string as `phone_country_code`.

## Fields

| # | JSON key | Label | Required? | Type / format | Error messages to show |
|---|---|---|---|---|---|
| 1 | `full_name` | Full Name | **Yes** | text, max 255 | "Full name is required." · "Full name cannot be empty." |
| 2 | `job_title` | Job Title | **Yes** | text, max 255 | "Job title is required." · "Job title cannot be empty." |
| 3 | `work_email` | Work Email | **Yes** | email | "Work email is required." · "Enter a valid email address." |
| 4a | `phone_country_code` | Phone country code (dropdown, e.g. "+91") | Conditional* | one of the `phone_country_codes` values | "Select a valid country code." · "Please select a country code for your phone number." |
| 4b | `phone_number` | Phone Number | Conditional* | **digits only, exactly 10** | "Phone number must contain only digits." · "Phone number must be exactly 10 digits." · "Please enter your phone number." |
| 5 | `linkedin_profile` | LinkedIn Profile | No | URL (must include `http(s)://`) | "Enter a valid LinkedIn URL, e.g. https://linkedin.com/in/username." |
| 6 | `company_name` | Company Name | **Yes** | text, max 255 | "Company name is required." · "Company name cannot be empty." |
| 7 | `website` | Website | **Yes** | URL (must include `http(s)://`) | "Website is required." · "Enter a valid website URL, e.g. https://example.com." |
| 8 | `country` | Country | **Yes** | must be one of the dropdown values | "Country is required." · "Invalid country name. Only country names are allowed." |
| 9 | `industry` | Industry | **Yes** | text, max 255 | "Industry is required." · "Industry cannot be empty." |
| 10 | `company_size` | Size | No | one of dropdown values | "Select a valid company size." |
| 11 | `year_founded` | Year Founded | No | integer, >= 1800 | "Enter a valid year." |
| 12 | `partner_type` | Partner Type | **Yes** | one of dropdown values | "Partner type is required." · "Select a valid partner type." |
| 13 | `why_partner` | Why Partner With Us? | **Yes** | text | "Please tell us why you want to partner with us." |
| 14 | `markets_regions` | Markets/Regions | **Yes** | text, max 255 | "Markets/regions is required." · "Markets/regions cannot be empty." |
| 15 | `target_customer` | Target Customer | No | text, max 255 | — |
| 16 | `promotion_plan` | Promotion Plan | No | text | — |
| 17 | `sells_similar_service` | Do you sell similar security service? | **Yes** | boolean (Yes/No radio) | "Please tell us if you sell a similar security service." |
| 18 | `estimated_referrals_per_year` | Estimated Referrals/Year | **Yes** | integer, >= 0 | "Estimated referrals per year is required." · "Enter a valid number." |
| 19 | `total_active_clients` | Total No of Active Clients | **Yes** | integer, >= 0 | "Total no of active clients is required." · "Enter a valid number." |
| 20 | `audience_description` | Audience Description | No | text | — |
| 21 | `agreed_privacy_policy` | Privacy Policy checkbox | **Yes**, must be `true` | boolean | "You must agree to the privacy policy to submit an application." |
| 22 | `consent_communications` | Communications consent checkbox | No | boolean | — |

\* Neither `phone_country_code` nor `phone_number` is required on its own —
but if either is filled in, the other becomes required too (you can't submit
a country code with no number, or a number with no country code selected).

## Frontend implementation notes

1. **Mark required fields with `*`** on the label for every row above marked "Yes" — currently the UI is missing the `*` on Website, Industry, Why Partner With Us, Markets/Regions, Estimated Referrals/Year, and Total No of Active Clients.
2. **Phone number input** — put the `phone_country_code` dropdown right before the number input (like the +91 example), and restrict the number input to digits only as the user types (don't just validate on submit):
   ```html
   <select name="phone_country_code">
     <!-- populated from GET /api/partners/form-options/ -> phone_country_codes, e.g. -->
     <option value="+91">India (+91)</option>
     <option value="+1">United States (+1)</option>
   </select>
   <input type="tel" inputmode="numeric" pattern="[0-9]*" maxlength="10"
          oninput="this.value = this.value.replace(/[^0-9]/g, '').slice(0, 10)">
   ```
   Show "Phone number must be exactly 10 digits." if the field is non-empty and length ≠ 10 on blur/submit.
3. **Website / LinkedIn inputs** — validate the value starts with `http://` or `https://` before submit; if the user types `vapt.ai` without a scheme, show the "Enter a valid website URL..." message rather than submitting.
4. **Submit flow**: do client-side checks first for instant feedback, but always handle the `400` response from the API too (e.g. if a bot/JS-disabled client bypasses client checks) — walk the JSON keys in the error response and show each message next to its field using the same copy as this table, so users never see two different wordings for the same problem.
5. Field names sent in the POST body must match the `JSON key` column exactly (snake_case) — that's what the backend serializer expects.
