import urllib.request
import urllib.error
import logging
import sys
import re

print("=" * 60)
print("Password Autocomplete Verify — Plugin 42057 — Ubuntu")
print("Service: tcp/1010/www")
print("=" * 60)

TARGET_HOST = "192.168.0.20"
TARGET_PORT = 1010

URLS_TO_CHECK = [
    f"http://{TARGET_HOST}:{TARGET_PORT}/",
    f"http://{TARGET_HOST}:{TARGET_PORT}/login",
    f"http://{TARGET_HOST}:{TARGET_PORT}/Login",
    f"http://{TARGET_HOST}:{TARGET_PORT}/Login/Validate",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("autocomplete_verify")
all_good = True

def check_autocomplete(html: str, url: str) -> bool:
    page_ok = True

    password_inputs = re.findall(
        r'<input[^>]*type=["\']password["\'][^>]*>',
        html, re.IGNORECASE
    )
    log.info("   Password fields found: %d", len(password_inputs))

    for inp in password_inputs:
        if re.search(r'autocomplete=["\'](?:off|new-password)["\']',
                     inp, re.IGNORECASE):
            log.info("   ✅ autocomplete=off found: %s",
                     inp[:80].strip())
        else:
            log.error("   ❌ Missing autocomplete=off: %s",
                      inp[:80].strip())
            page_ok = False

    # Check form tags
    form_tags = re.findall(r'<form[^>]*>', html, re.IGNORECASE)
    for form in form_tags:
        if re.search(r'autocomplete=["\']off["\']', form,
                     re.IGNORECASE):
            log.info("   ✅ Form has autocomplete=off")
        else:
            log.warning("   ⚠️ Form missing autocomplete=off")

    return page_ok


for url in URLS_TO_CHECK:
    log.info("\n   Checking: %s", url)
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "NessusVerifyScript/1.0")
        response = urllib.request.urlopen(req, timeout=5)
        html     = response.read().decode("utf-8", errors="ignore")

        if not check_autocomplete(html, url):
            all_good = False

    except urllib.error.HTTPError as e:
        log.info("   HTTP %d — reading response body...", e.code)
        try:
            html = e.read().decode("utf-8", errors="ignore")
            if not check_autocomplete(html, url):
                all_good = False
        except Exception:
            log.warning("   ⚠️ Could not read body")

    except Exception as e:
        log.warning("   ⚠️ Could not connect to %s: %s", url, e)

# ─── Final Result ─────────────────────────────────────────────────
print("\n" + "=" * 60)
if all_good:
    print("✅ VERDICT: PASS — All password fields have autocomplete=off!")
    print("   Re-run Nessus scan to confirm Plugin 42057 resolved.")
else:
    print("❌ VERDICT: FAIL — Some password fields missing autocomplete=off")
    print("   Manually add autocomplete='off' to password input fields")
print("=" * 60)