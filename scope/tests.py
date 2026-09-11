"""
Unit tests for scope/utils.py's target validation.

Real bug report: manual/file scope uploads with completely legitimate-
looking content (zero-padded IPs, a trailing comma from a CSV export, a
bare hostname with no dot) were coming back "No valid targets found in the
uploaded file" because validate_entry() rejected anything that didn't
match a strict IP/CIDR/URL shape. Fixed to accept any non-empty target —
these tests lock that in.
"""
import io
import unittest
from unittest.mock import patch

from scope.utils import parse_file_content, process_entries, validate_entry


class _FakeUploadedFile:
    """Minimal stand-in for Django's UploadedFile — parse_file_content only
    ever calls .read() and .seek() on it."""

    def __init__(self, data: bytes):
        self._data = data

    def read(self):
        return self._data

    def seek(self, pos):
        pass


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


class ParseFileContentExcelMultiSheetTests(unittest.TestCase):
    """
    Real bug report: a real scope workbook ("AEC VAPT scope.xlsx") spread
    its content across 4 tabs — a text-only cover/summary sheet first,
    then the actual "Asset list" sheet with every real target, then two
    near-empty sheets. pd.read_excel() with no sheet_name= reads ONLY the
    first sheet by default, so every real target on the other sheets was
    silently dropped — the summary sheet alone has zero IP-shaped content,
    which is exactly what produced "No valid targets found in the
    uploaded file" even though the workbook clearly had 20 real assets in
    it. Also covers a single cell holding multiple newline-separated IPs
    (a real "Management / Target IP" cell listing a private IP plus
    several public IPs on one cell, confirmed in that same file).
    """

    def _build_workbook(self) -> bytes:
        openpyxl = _import_openpyxl_or_skip()
        wb = openpyxl.Workbook()

        cover = wb.active
        cover.title = "Scope"
        cover["B2"] = "For quick reference, here is our agreed baseline scope:"
        cover["B4"] = "Target Assets (2 Total): 1 Firewall and 1 Server"

        assets = wb.create_sheet("Asset list")
        assets.append(["Asset #", "Asset Category", "Management / Target IP"])
        # One cell holding multiple newline-separated targets — private IP
        # plus a "Public IP:" label line plus two public IPs, exactly the
        # real-world shape found in the actual uploaded file.
        assets["C2"] = "FW-01"
        assets["A2"] = "FW-01"
        assets["B2"] = "Firewall"
        assets["C2"] = "172.16.2.250\n\nPublic IP:\n203.177.12.162\n203.177.12.163"
        assets.append(["PS-01", "Physical Server", "172.16.1.222"])

        wb.create_sheet("network diagram")  # empty sheet, like the real file

        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()

    def test_targets_on_a_later_sheet_are_not_dropped(self):
        data = self._build_workbook()
        values = parse_file_content(_FakeUploadedFile(data), "scope.xlsx")

        # Every real IP from the SECOND sheet must be present — this is
        # exactly what used to be silently missed.
        for expected_ip in ("172.16.2.250", "203.177.12.162", "203.177.12.163", "172.16.1.222"):
            self.assertIn(expected_ip, values, f"{expected_ip} missing — sheet 2 was not read")

    def test_multiline_cell_is_split_into_separate_targets(self):
        data = self._build_workbook()
        values = parse_file_content(_FakeUploadedFile(data), "scope.xlsx")
        # The "Public IP:" label line inside that same cell should also
        # come through as its own line (harmless — validate_entry accepts
        # it as generic text), but the 3 real IPs must each be their own
        # separate, independently-usable entry rather than one blob.
        self.assertNotIn(
            "172.16.2.250\n\nPublic IP:\n203.177.12.162\n203.177.12.163",
            values,
        )


def _import_openpyxl_or_skip():
    try:
        import openpyxl
        return openpyxl
    except ImportError:
        raise unittest.SkipTest("openpyxl not installed")


class ParseFileContentExtraFormatsTests(unittest.TestCase):
    """
    Real feature request: scope file upload should accept every format
    Upload Report's own upload does (UploadReportView.ALLOWED_EXTENSIONS)
    — pdf, excel, csv, nessus, html, doc — not just csv/xlsx/xls/txt.
    """

    def test_html_table_content_extracted(self):
        html = b"""<html><body>
        <table><tr><td>192.168.1.10</td><td>web-server-01</td></tr></table>
        </body></html>"""
        values = parse_file_content(_FakeUploadedFile(html), "assets.html")
        self.assertIn("192.168.1.10", values)
        self.assertIn("web-server-01", values)

    def test_nessus_xml_host_ip_tag_extracted(self):
        # Real .nessus structure: the target IP is TEXT CONTENT inside a
        # <tag name="host-ip"> element, not a one-per-line plain value.
        xml = b"""<NessusClientData_v2><Report><ReportHost name="host1">
        <HostProperties><tag name="host-ip">172.16.0.5</tag></HostProperties>
        </ReportHost></Report></NessusClientData_v2>"""
        values = parse_file_content(_FakeUploadedFile(xml), "scan.nessus")
        self.assertIn("172.16.0.5", values)

    def test_pdf_delegates_to_upload_report_parser_and_splits_lines(self):
        # Reuses upload_report.parsers.parse_pdf's text extraction rather
        # than reimplementing PDF parsing — mocked here so this test
        # doesn't need a real PDF file, just verifies the wiring.
        with patch(
            "upload_report.parsers.parse_pdf",
            return_value={"type": "pdf", "text_full": "192.168.1.20\nfinance-server\n"},
        ) as mock_pdf:
            values = parse_file_content(_FakeUploadedFile(b"%PDF-fake"), "assets.pdf")
        self.assertTrue(mock_pdf.called)
        self.assertIn("192.168.1.20", values)
        self.assertIn("finance-server", values)

    def test_docx_delegates_to_upload_report_parser(self):
        with patch(
            "upload_report.parsers.parse_docx",
            return_value={"type": "docx", "text_full": "10.0.0.99\n"},
        ) as mock_docx:
            values = parse_file_content(_FakeUploadedFile(b"fake-docx"), "assets.docx")
        self.assertTrue(mock_docx.called)
        self.assertIn("10.0.0.99", values)

    def test_doc_parser_error_propagates_as_value_error(self):
        # e.g. antiword not installed on the server — parse_doc's own
        # documented failure mode; must surface as a clean error, not a
        # silent empty result.
        with patch(
            "upload_report.parsers.parse_doc",
            return_value={"error": "antiword not installed"},
        ):
            with self.assertRaises(ValueError):
                parse_file_content(_FakeUploadedFile(b"fake-doc"), "assets.doc")
