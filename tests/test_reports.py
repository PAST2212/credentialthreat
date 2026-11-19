import csv
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from credentialthreat.core import files


class ReportTests(unittest.TestCase):
    def test_one_four_column_row_per_candidate_with_no_secret_or_full_url(self):
        marker = "PRIVATEFIXTUREONLY"
        origin = "https://account:" + marker + "@docs.example.com/page?" + marker
        resource = "https://static.example.com/path/" + marker + "#" + marker
        matches = [("api_key", marker), ("public_key", marker)]
        with TemporaryDirectory() as root, patch.object(files, "OUTPUT_DIRECORY", Path(root)):
            files.ManageFiles.create_csv_result_file()
            files.ManageFiles.write_csv_result_file([(origin, resource, matches)])
            report, = Path(root).glob("*.csv")
            with report.open(newline="") as stream:
                header, *rows = csv.reader(stream, delimiter=";")
        self.assertEqual(len(header), 4)
        self.assertEqual(len(rows), 2)
        self.assertNotIn(marker, repr(rows))
        for row, label in zip(rows, ("api_key", "public_key"), strict=True):
            self.assertEqual(row[:3], ["https://docs.example.com", "https://static.example.com", "example.com"])
            self.assertEqual(len(row), 4)
            self.assertIn(label, row[3])
            self.assertIn("Unverified", row[3])
        self.assertIn("may identify public material", rows[1][3])
        self.assertNotIn("may identify public material", rows[0][3])

    def test_combined_categories_share_a_row_and_retain_public_material_context(self):
        origin = "https://docs.example.com"
        matches = [("public_key + aws_keys", "[REDACTED]")]
        with TemporaryDirectory() as root, patch.object(files, "OUTPUT_DIRECORY", Path(root)):
            files.ManageFiles.write_csv_result_file([(origin, origin, matches)])
            report, = Path(root).glob("*.csv")
            with report.open(newline="") as stream:
                header, row = csv.reader(stream, delimiter=";")
        self.assertEqual(len(header), 4)
        self.assertEqual(row, [
            origin, origin, "example.com",
            "Unverified public_key + aws_keys [REDACTED] (label may identify public material)",
        ])

    def test_configured_subdomain_is_not_widened_to_its_parent(self):
        with TemporaryDirectory() as root, patch.object(files, "INPUT_DIRECORY", Path(root)):
            (Path(root) / "domains.txt").write_text("# local scope\nDocs.Example.com\n", encoding="utf-8")
            self.assertEqual(files.ManageFiles().get_domains(), ["docs.example.com"])

    def test_international_scope_matches_the_http_client_spelling(self):
        from yarl import URL
        host = "faß.example.com"
        with TemporaryDirectory() as root, patch.object(files, "INPUT_DIRECORY", Path(root)):
            (Path(root) / "domains.txt").write_text(host, encoding="utf-8")
            self.assertEqual(files.ManageFiles().get_domains(), [URL("https://" + host).raw_host])

    def test_public_suffix_or_malformed_entry_cannot_enable_a_partial_scan(self):
        with TemporaryDirectory() as root, patch.object(files, "INPUT_DIRECORY", Path(root)):
            for entry in ("com", "github.io", "*.example.com", "https://docs.example.com/a"):
                with self.subTest(entry=entry):
                    (Path(root) / "domains.txt").write_text("docs.example.com\n" + entry)
                    with self.assertRaisesRegex(ValueError, "line 2"):
                        files.ManageFiles().get_domains()

    def test_first_run_creates_report_and_reopening_preserves_rows(self):
        with TemporaryDirectory() as root:
            output = Path(root) / "data" / "output"
            with patch.object(files, "OUTPUT_DIRECORY", output):
                files.ManageFiles.create_csv_result_file()
                report, = output.glob("Credential_Leak_Candidates_*.csv")
                with report.open("a", newline="") as stream:
                    csv.writer(stream, delimiter=";").writerow(["synthetic"] * 4)
                files.ManageFiles.create_csv_result_file()
                with report.open(newline="") as stream:
                    self.assertEqual(list(csv.reader(stream, delimiter=";")), [
                        ["Base URL", "Affected Network Resource from Base URL",
                         "Registered Domain Base URL", "Credential Leak Candidate"],
                        ["synthetic"] * 4,
                    ])
