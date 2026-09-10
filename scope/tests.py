"""
Unit tests for scope/utils.py's target validation.

Real bug report: manual/file scope uploads with completely legitimate-
looking content (zero-padded IPs, a trailing comma from a CSV export, a
bare hostname with no dot) were coming back "No valid targets found in the
uploaded file" because validate_entry() rejected anything that didn't
match a strict IP/CIDR/URL shape. Fixed to accept any non-empty target —
these tests lock that in.
"""
import unittest

from scope.utils import process_entries, validate_entry


class ValidateEntryAcceptsAnyNonEmptyTargetTests(unittest.TestCase):
    def test_plain_ip_is_valid(self):
        self.assertEqual(validate_entry("192.168.1.1", "internal_ip"), (True, ""))

    def test_subnet_is_valid(self):
        self.assertEqual(validate_entry("10.0.0.0/24", "subnet"), (True, ""))

    def test_url_is_valid(self):
        self.assertEqual(validate_entry("https://example.com", "web_url"), (True, ""))

    def test_zero_padded_ip_no_longer_rejected(self):
        # Python's ipaddress module rejects leading-zero octets outright —
        # this used to fail is_valid_ip() and come back "Invalid IP address".
        is_valid, error = validate_entry("192.168.001.001", "external_ip")
        self.assertTrue(is_valid)
        self.assertEqual(error, "")

    def test_trailing_comma_from_csv_export_no_longer_rejected(self):
        is_valid, error = validate_entry("192.168.1.1,", "external_ip")
        self.assertTrue(is_valid)

    def test_bare_hostname_with_no_dot_no_longer_rejected(self):
        # Doesn't match is_valid_url's "word.word" shape at all.
        is_valid, error = validate_entry("webserver01", "external_ip")
        self.assertTrue(is_valid)

    def test_asset_name_no_longer_rejected(self):
        is_valid, error = validate_entry("Finance-DB-Prod", "external_ip")
        self.assertTrue(is_valid)

    def test_only_truly_empty_value_is_rejected(self):
        self.assertEqual(validate_entry("", "external_ip"), (False, "Value cannot be empty"))
        self.assertEqual(validate_entry("   ", "external_ip"), (False, "Value cannot be empty"))


class ProcessEntriesRealisticFileTests(unittest.TestCase):
    def test_realistic_uploaded_file_rows_all_pass(self):
        # A representative mix of what a real uploaded scope file looks
        # like — this used to leave every one of these rows classified
        # is_valid=False, so ScopeCreateAPIView's `new_entry_values` ended
        # up empty and the whole upload failed with "No valid targets
        # found in the uploaded file" even though the file clearly had
        # real content in it.
        rows = [
            "192.168.001.001",
            "10.0.0.5,",
            "webserver01",
            "Finance-DB-Prod",
            "example.com",
            "  ",          # blank line in the file — should just be dropped
        ]
        processed = process_entries(rows, expand_subnets=False)
        valid_values = {p["value"] for p in processed if p["is_valid"]}
        # 5 real rows in, 1 blank line correctly excluded, none rejected
        # for "wrong format".
        self.assertEqual(len(processed), 5)
        self.assertTrue(all(p["is_valid"] for p in processed))
        self.assertIn("192.168.001.001", valid_values)
        self.assertIn("10.0.0.5,", valid_values)
        self.assertIn("webserver01", valid_values)

    def test_subnet_expansion_still_works_for_genuine_cidr(self):
        # Real CIDR input should still expand into individual IPs exactly
        # like before — this fix only relaxed what counts as "valid", it
        # didn't touch subnet detection/expansion.
        processed = process_entries(["10.0.0.0/24"], expand_subnets=True)
        self.assertEqual(len(processed), 254)
        self.assertTrue(all(p["is_valid"] for p in processed))
        self.assertTrue(all(p["expanded_from"] == "10.0.0.0/24" for p in processed))
