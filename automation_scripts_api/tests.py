"""
Unit tests for the AI Automation download/view endpoints
(admin_view_ai_automation, user_download_ai_automation_script).

MongoContext and billing.enforcement.assert_can_use_automation_scripts /
_resolve_admin_and_teams are all mocked out — these tests never touch a
real Mongo cluster, OpenAI, or the Django user database, so they run fast
and don't need Atlas credentials.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from automation_scripts_api import views as automation_views


def _fake_user(*, is_staff=False, is_superuser=False, user_id="admin-1", email="admin@example.com"):
    return SimpleNamespace(
        id=user_id,
        email=email,
        is_staff=is_staff,
        is_superuser=is_superuser,
        is_authenticated=True,
    )


class _FakeMongoContext:
    """Drop-in for `with MongoContext() as db:` returning a canned db dict
    of {collection_name: MagicMock-with-find_one/update_one}."""

    def __init__(self, collections):
        self._collections = collections

    def __enter__(self):
        return self._collections

    def __exit__(self, *exc):
        return False


def _mongo_ctx_factory(collections):
    return lambda *a, **kw: _FakeMongoContext(collections)


FULL_AUTOMATION_CARD = {
    "vulnerability": "Weak TLS Cipher",
    "os": "Ubuntu 22.04",
    "automation_status": "full",
    "automation_possible": "Yes",
    "reason_not_possible": "",
    "script_description": "Disables weak ciphers.",
    "language": "bash",
    "fix_script": "#!/bin/bash\necho fixing",
    "fix_script_filename": "Weak_TLS_Cipher_Ubuntu_22_04_fix.sh",
    "verify_script": "#!/bin/bash\necho verifying",
    "verify_script_filename": "Weak_TLS_Cipher_Ubuntu_22_04_verify.sh",
    "download_count": 0,
}

NOT_POSSIBLE_CARD = {
    "vulnerability": "Default Creds on Vendor Portal",
    "os": "FortiOS",
    "automation_status": "not_possible",
    "automation_possible": "No",
    "reason_not_possible": "Requires vendor-portal login; cannot be scripted unattended.",
    "fix_script": "",
    "fix_script_filename": "",
    "verify_script": "",
    "verify_script_filename": "",
}


class AdminViewAiAutomationTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def _call(self, user, card_id="card-1"):
        request = self.factory.get(f"/api/admin/automation-scripts/ai/{card_id}/")
        force_authenticate(request, user=user)
        request.user = user
        return automation_views.admin_view_ai_automation(request, card_id)

    def test_non_admin_caller_gets_403(self):
        response = self._call(_fake_user(is_staff=False, is_superuser=False))
        self.assertEqual(response.status_code, 403)

    def test_card_not_found_gets_404(self):
        collections = {automation_views.VULN_CARD_COLLECTION: MagicMock(find_one=MagicMock(return_value=None))}
        with patch.object(automation_views, "MongoContext", _mongo_ctx_factory(collections)):
            response = self._call(_fake_user(is_staff=True))
        self.assertEqual(response.status_code, 404)

    def test_card_with_no_automation_card_yet_gets_404(self):
        card = {"card_id": "card-1", "admin_id": "admin-1", "automation_card": {}}
        collections = {automation_views.VULN_CARD_COLLECTION: MagicMock(find_one=MagicMock(return_value=card))}
        with patch.object(automation_views, "MongoContext", _mongo_ctx_factory(collections)):
            response = self._call(_fake_user(is_staff=True))
        self.assertEqual(response.status_code, 404)

    def test_premium_admin_sees_automation_details_without_script_bodies(self):
        card = {"card_id": "card-1", "admin_id": "admin-1", "automation_card": dict(FULL_AUTOMATION_CARD)}
        collections = {automation_views.VULN_CARD_COLLECTION: MagicMock(find_one=MagicMock(return_value=card))}
        with patch.object(automation_views, "MongoContext", _mongo_ctx_factory(collections)), \
             patch.object(automation_views, "_premium_required_message", return_value=(False, None)):
            response = self._call(_fake_user(is_staff=True))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["matched"])
        self.assertFalse(response.data["premium_required"])
        self.assertEqual(response.data["automation_status"], "full")
        self.assertNotIn("fix_script", response.data)
        self.assertNotIn("verify_script", response.data)

    def test_freemium_admin_gets_locked_message_but_still_sees_status(self):
        card = {"card_id": "card-1", "admin_id": "admin-1", "automation_card": dict(FULL_AUTOMATION_CARD)}
        collections = {automation_views.VULN_CARD_COLLECTION: MagicMock(find_one=MagicMock(return_value=card))}
        with patch.object(automation_views, "MongoContext", _mongo_ctx_factory(collections)), \
             patch.object(automation_views, "_premium_required_message", return_value=(True, "Upgrade to Premium.")):
            response = self._call(_fake_user(is_staff=True))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["premium_required"])
        self.assertEqual(response.data["message"], "Upgrade to Premium.")
        # Status is still visible even when locked — only script bodies are gated.
        self.assertEqual(response.data["automation_status"], "full")


class UserDownloadAiAutomationScriptTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def _call(self, user, card_id="card-1", query=""):
        request = self.factory.get(f"/api/user/automation-scripts/ai/{card_id}/download/{query}")
        force_authenticate(request, user=user)
        request.user = user
        return automation_views.user_download_ai_automation_script(request, card_id)

    def test_admin_caller_is_blocked(self):
        response = self._call(_fake_user(is_staff=True))
        self.assertEqual(response.status_code, 403)

    def test_member_with_no_resolvable_admin_is_blocked(self):
        with patch.object(automation_views, "_resolve_admin_and_teams", return_value=(None, None, [])):
            response = self._call(_fake_user())
        self.assertEqual(response.status_code, 403)

    def test_freemium_member_blocked_by_plan_gate(self):
        from billing.enforcement import PlanLimitExceeded
        with patch.object(automation_views, "_resolve_admin_and_teams", return_value=("admin-1", "a@x.com", ["Network Security"])), \
             patch("billing.enforcement.assert_can_use_automation_scripts", side_effect=PlanLimitExceeded("Upgrade to Premium.")):
            response = self._call(_fake_user())
        self.assertEqual(response.status_code, 403)

    def test_card_not_found(self):
        collections = {automation_views.VULN_CARD_COLLECTION: MagicMock(find_one=MagicMock(return_value=None))}
        with patch.object(automation_views, "_resolve_admin_and_teams", return_value=("admin-1", "a@x.com", ["Network Security"])), \
             patch("billing.enforcement.assert_can_use_automation_scripts"), \
             patch.object(automation_views, "MongoContext", _mongo_ctx_factory(collections)):
            response = self._call(_fake_user())
        self.assertEqual(response.status_code, 404)

    def test_not_possible_card_returns_reason_not_a_file(self):
        card = {"card_id": "card-1", "admin_id": "admin-1", "automation_card": dict(NOT_POSSIBLE_CARD)}
        collections = {automation_views.VULN_CARD_COLLECTION: MagicMock(find_one=MagicMock(return_value=card))}
        with patch.object(automation_views, "_resolve_admin_and_teams", return_value=("admin-1", "a@x.com", ["Network Security"])), \
             patch("billing.enforcement.assert_can_use_automation_scripts"), \
             patch.object(automation_views, "MongoContext", _mongo_ctx_factory(collections)):
            response = self._call(_fake_user())
        self.assertEqual(response.status_code, 404)
        self.assertIn("vendor-portal", response.data["error"])

    def test_invalid_type_param_returns_400(self):
        card = {"card_id": "card-1", "admin_id": "admin-1", "automation_card": dict(FULL_AUTOMATION_CARD)}
        collections = {automation_views.VULN_CARD_COLLECTION: MagicMock(find_one=MagicMock(return_value=card))}
        with patch.object(automation_views, "_resolve_admin_and_teams", return_value=("admin-1", "a@x.com", ["Network Security"])), \
             patch("billing.enforcement.assert_can_use_automation_scripts"), \
             patch.object(automation_views, "MongoContext", _mongo_ctx_factory(collections)):
            response = self._call(_fake_user(), query="?type=nonsense")
        self.assertEqual(response.status_code, 400)

    def test_successful_fix_script_download(self):
        card = {"card_id": "card-1", "admin_id": "admin-1", "automation_card": dict(FULL_AUTOMATION_CARD)}
        update_one = MagicMock()
        collections = {
            automation_views.VULN_CARD_COLLECTION: MagicMock(
                find_one=MagicMock(return_value=card), update_one=update_one
            )
        }
        with patch.object(automation_views, "_resolve_admin_and_teams", return_value=("admin-1", "a@x.com", ["Network Security"])), \
             patch("billing.enforcement.assert_can_use_automation_scripts"), \
             patch.object(automation_views, "MongoContext", _mongo_ctx_factory(collections)):
            response = self._call(_fake_user(), query="?type=fix")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), FULL_AUTOMATION_CARD["fix_script"])
        self.assertIn(FULL_AUTOMATION_CARD["fix_script_filename"], response["Content-Disposition"])
        self.assertEqual(response["Content-Disposition"][:10], "attachment")
        # download_count bumped via $inc, scoped to this exact card.
        update_one.assert_called_once()
        args, kwargs = update_one.call_args
        self.assertEqual(args[0], {"card_id": "card-1"})
        self.assertEqual(args[1]["$inc"], {"automation_card.download_count": 1})

    def test_successful_verify_script_download_defaults_type_to_fix_when_omitted(self):
        card = {"card_id": "card-1", "admin_id": "admin-1", "automation_card": dict(FULL_AUTOMATION_CARD)}
        collections = {
            automation_views.VULN_CARD_COLLECTION: MagicMock(
                find_one=MagicMock(return_value=card), update_one=MagicMock()
            )
        }
        with patch.object(automation_views, "_resolve_admin_and_teams", return_value=("admin-1", "a@x.com", ["Network Security"])), \
             patch("billing.enforcement.assert_can_use_automation_scripts"), \
             patch.object(automation_views, "MongoContext", _mongo_ctx_factory(collections)):
            response = self._call(_fake_user())  # no ?type= at all
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), FULL_AUTOMATION_CARD["fix_script"])

    def test_missing_script_for_requested_type_returns_404(self):
        partial_card = dict(FULL_AUTOMATION_CARD)
        partial_card["verify_script"] = ""
        partial_card["verify_script_filename"] = ""
        card = {"card_id": "card-1", "admin_id": "admin-1", "automation_card": partial_card}
        collections = {automation_views.VULN_CARD_COLLECTION: MagicMock(find_one=MagicMock(return_value=card))}
        with patch.object(automation_views, "_resolve_admin_and_teams", return_value=("admin-1", "a@x.com", ["Network Security"])), \
             patch("billing.enforcement.assert_can_use_automation_scripts"), \
             patch.object(automation_views, "MongoContext", _mongo_ctx_factory(collections)):
            response = self._call(_fake_user(), query="?type=verify")
        self.assertEqual(response.status_code, 404)
