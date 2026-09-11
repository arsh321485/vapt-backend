"""
Unit tests for the AI Automation feature (Automation Engineer agent +
automation_card parsing/persistence). Pure unit tests — no real Mongo /
OpenAI / Django DB access, so these run fast and don't need a live
Atlas cluster or a test database.

Covers:
  - upload_report/crew_agent/agents.py, tasks.py: the new 6th agent/task
    is additive and doesn't disturb the existing 5-agent/4-task crew or
    which task ends up "last" (task_format — the crew's final result).
  - upload_report/mitigation_tool.py: _parse_automation_card and its
    helpers, including the "not_possible must never carry a script"
    safety net.
"""
import json
import unittest

from upload_report.mitigation_tool import (
    _automation_script_extension,
    _automation_script_filename,
    _normalize_automation_status,
    _parse_automation_card,
)


class NormalizeAutomationStatusTests(unittest.TestCase):
    def test_yes_maps_to_full(self):
        self.assertEqual(_normalize_automation_status("Yes"), "full")
        self.assertEqual(_normalize_automation_status("yes"), "full")

    def test_partial_maps_to_partial(self):
        self.assertEqual(_normalize_automation_status("Partial"), "partial")

    def test_no_and_unrecognized_map_to_not_possible(self):
        self.assertEqual(_normalize_automation_status("No"), "not_possible")
        self.assertEqual(_normalize_automation_status(""), "not_possible")
        self.assertEqual(_normalize_automation_status("garbage"), "not_possible")
        self.assertEqual(_normalize_automation_status(None), "not_possible")


class AutomationScriptExtensionTests(unittest.TestCase):
    def test_language_to_extension(self):
        self.assertEqual(_automation_script_extension("bash"), "sh")
        self.assertEqual(_automation_script_extension("Bash"), "sh")
        self.assertEqual(_automation_script_extension("PowerShell"), "ps1")
        self.assertEqual(_automation_script_extension("python"), "py")
        self.assertEqual(_automation_script_extension("vendor_cli"), "txt")
        self.assertEqual(_automation_script_extension(""), "txt")
        self.assertEqual(_automation_script_extension(None), "txt")


class AutomationScriptFilenameTests(unittest.TestCase):
    def test_builds_filename_from_vuln_and_os(self):
        automation = {"vulnerability": "Weak TLS Cipher", "os": "Ubuntu 22.04", "language": "bash"}
        name = _automation_script_filename(automation, "#!/bin/bash\necho hi", "fix")
        self.assertTrue(name.startswith("Weak_TLS_Cipher_Ubuntu_22_04_fix"))
        self.assertTrue(name.endswith(".sh"))

    def test_empty_script_content_yields_empty_filename(self):
        automation = {"vulnerability": "Weak TLS Cipher", "os": "Ubuntu 22.04", "language": "bash"}
        self.assertEqual(_automation_script_filename(automation, "", "fix"), "")
        self.assertEqual(_automation_script_filename(automation, "   ", "fix"), "")
        self.assertEqual(_automation_script_filename(automation, None, "fix"), "")

    def test_sanitizes_special_characters(self):
        automation = {"vulnerability": "SSL/TLS: Weak Cipher (RC4)!", "os": "Windows Server 2019", "language": "powershell"}
        name = _automation_script_filename(automation, "Write-Host fix", "verify")
        # No slashes, colons, parens, spaces, etc. left in the filename.
        for bad_char in "/\\:()! ":
            self.assertNotIn(bad_char, name)
        self.assertTrue(name.endswith("_verify.ps1"))


class ParseAutomationCardTests(unittest.TestCase):
    def _full_automation_obj(self, **overrides):
        obj = {
            "vulnerability": "Weak TLS Cipher",
            "os": "Ubuntu 22.04",
            "severity": "Medium",
            "port": "443/tcp",
            "description": "Server supports weak TLS ciphers.",
            "automation_status": "full",
            "automation_possible": "Yes",
            "reason_not_possible": "",
            "script_name": "disable_weak_ciphers.sh",
            "script_description": "Disables weak TLS ciphers in nginx.",
            "what_can_be_automated": "All of it.",
            "what_must_remain_manual": "",
            "recommended_approach": "Run the fix script, then verify.",
            "considerations_before": "Back up nginx.conf first.",
            "considerations_after": "Restart nginx and re-scan.",
            "language": "bash",
            "libraries": "",
            "command_download_libraries": "",
            "command_run_script": "bash fix.sh",
            "fix_script": "#!/bin/bash\necho fixing",
            "verify_script": "#!/bin/bash\necho verifying",
        }
        obj.update(overrides)
        return obj

    def test_full_automation_plain_json(self):
        raw = json.dumps({"automation": self._full_automation_obj()})
        card = _parse_automation_card(raw)
        self.assertEqual(card["automation_status"], "full")
        self.assertEqual(card["automation_possible"], "Yes")
        self.assertIn("echo fixing", card["fix_script"])
        self.assertIn("echo verifying", card["verify_script"])
        self.assertTrue(card["fix_script_filename"].endswith(".sh"))
        self.assertTrue(card["verify_script_filename"].endswith(".sh"))
        self.assertEqual(card["tested_manually"], "No — AI-generated, not yet human-tested")
        self.assertEqual(card["download_count"], 0)
        self.assertIn("generated_at", card)

    def test_full_automation_inside_markdown_fences(self):
        raw = "```json\n" + json.dumps({"automation": self._full_automation_obj()}) + "\n```"
        card = _parse_automation_card(raw)
        self.assertEqual(card["automation_status"], "full")
        self.assertIn("echo fixing", card["fix_script"])

    def test_bare_json_object_scan_fallback(self):
        obj = self._full_automation_obj(automation_status="partial", automation_possible="Partial")
        raw = "Here is my analysis:\n" + json.dumps({"automation": obj}) + "\nThanks."
        card = _parse_automation_card(raw)
        self.assertEqual(card["automation_status"], "partial")

    def test_unwrapped_object_without_automation_key(self):
        # Some LLM outputs might return the inner object directly instead
        # of wrapped under "automation" — parser should still find it.
        obj = self._full_automation_obj()
        raw = json.dumps(obj)
        card = _parse_automation_card(raw)
        self.assertEqual(card["automation_status"], "full")
        self.assertEqual(card["vulnerability"], "Weak TLS Cipher")

    def test_not_possible_forces_scripts_and_filenames_empty(self):
        # Safety net: even if the LLM misbehaves and still returns script
        # content for a "No" verdict, it must never reach the stored card.
        obj = self._full_automation_obj(
            automation_status="not_possible",
            automation_possible="No",
            reason_not_possible="Requires a vendor-portal login; cannot be scripted unattended.",
            fix_script="echo should never appear",
            verify_script="echo should never appear either",
        )
        raw = json.dumps({"automation": obj})
        card = _parse_automation_card(raw)
        self.assertEqual(card["automation_status"], "not_possible")
        self.assertEqual(card["fix_script"], "")
        self.assertEqual(card["verify_script"], "")
        self.assertEqual(card["fix_script_filename"], "")
        self.assertEqual(card["verify_script_filename"], "")
        self.assertIn("vendor-portal", card["reason_not_possible"])

    def test_reason_not_possible_dropped_when_status_is_not_not_possible(self):
        # A stray reason_not_possible on a "full"/"partial" card shouldn't
        # be surfaced — it only means something when status is not_possible.
        obj = self._full_automation_obj(reason_not_possible="leftover text")
        raw = json.dumps({"automation": obj})
        card = _parse_automation_card(raw)
        self.assertEqual(card["reason_not_possible"], "")

    def test_missing_automation_status_is_derived_from_automation_possible(self):
        obj = self._full_automation_obj(automation_possible="Partial")
        del obj["automation_status"]
        raw = json.dumps({"automation": obj})
        card = _parse_automation_card(raw)
        self.assertEqual(card["automation_status"], "partial")

    def test_empty_input_returns_empty_dict(self):
        self.assertEqual(_parse_automation_card(""), {})
        self.assertEqual(_parse_automation_card(None), {})
        self.assertEqual(_parse_automation_card("   "), {})

    def test_garbage_input_returns_empty_dict(self):
        self.assertEqual(_parse_automation_card("this is not json at all"), {})

    def test_malformed_json_returns_empty_dict(self):
        self.assertEqual(_parse_automation_card('{"automation": {"vulnerability": '), {})


class CrewAgentWiringTests(unittest.TestCase):
    """
    Confirms the additive contract: the new agent/task don't remove or
    reorder the existing 5 agents / 4 tasks, and task_format (whose output
    the crew's own final result is read from — see mitigation_tool.py's
    `str(crew.kickoff())`) is still the LAST task in the list.
    """

    def setUp(self):
        from upload_report.crew_agent.agents import build_agents
        from upload_report.crew_agent.tasks import build_tasks

        class _DummyLLM:
            pass

        self.agents = build_agents(_DummyLLM())
        self.finding = {
            "ip": "10.0.0.5",
            "affected_hosts": ["10.0.0.5"],
            "vuln_names": [],
            "os": "Ubuntu 22.04",
            "port": "443/tcp",
            "vuln_name": "Weak TLS Cipher",
            "description": "desc",
            "plugin_output": "out",
            "assigned_to": "Network Security",
        }
        self.tasks, self.automation_task = build_tasks(self.agents, self.finding)

    def test_existing_five_agents_still_present(self):
        for key in (
            "vulnerability_analyst", "os_profiler", "remediation_engineer",
            "card_formatter", "backup_engineer",
        ):
            self.assertIn(key, self.agents)

    def test_automation_engineer_added(self):
        self.assertIn("automation_engineer", self.agents)
        self.assertEqual(len(self.agents), 6)

    def test_six_tasks_returned(self):
        self.assertEqual(len(self.tasks), 6)

    def test_task_format_is_still_last(self):
        # Card Formatter/QA must remain the last task — that's what the
        # crew's own final result (str(crew.kickoff())) is read from.
        self.assertEqual(self.tasks[-1].agent.role, "Mitigation Card Formatter and QA Reviewer")

    def test_task_automation_is_async_and_positioned_after_remediate(self):
        automation_task = self.tasks[4]
        self.assertEqual(automation_task.agent.role, "Automation Feasibility Analyst and Script Engineer")
        self.assertTrue(automation_task.async_execution)
        self.assertIs(automation_task, self.automation_task)

    def test_backup_task_still_async_unchanged(self):
        backup_task = self.tasks[2]
        self.assertEqual(backup_task.agent.role, "Backup and Recovery Engineer")
        self.assertTrue(backup_task.async_execution)

    def test_include_automation_false_omits_automation_task(self):
        from upload_report.crew_agent.tasks import build_tasks
        tasks, automation_task = build_tasks(self.agents, self.finding, include_automation=False)
        self.assertEqual(len(tasks), 5)
        self.assertIsNone(automation_task)
        self.assertEqual(tasks[-1].agent.role, "Mitigation Card Formatter and QA Reviewer")
        roles = [t.agent.role for t in tasks]
        self.assertNotIn("Automation Feasibility Analyst and Script Engineer", roles)
