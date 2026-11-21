from collections import Counter
from contextlib import redirect_stdout
from io import StringIO
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock

from credential_corpus import PAGES, RULES
from measure_rules import Scanner, measure, observations, print_score
from http_doubles import response


async def worker_findings(scanner, page):
    request = MagicMock()
    request.__aenter__.return_value = response(200, page.html)
    url = "https://fixture.invalid/" + page.name
    result = await scanner._get_request((url, url), {}, Mock(get=Mock(return_value=request)))
    return result[2] if result else []


class BenchmarkTests(unittest.IsolatedAsyncioTestCase):
    async def test_debug_configuration_and_mismatched_pem_blocks(self):
        expected = {
            "debug-option": [], "mixed-script": ["api_key", "jwt"], "next-property": [], "id-presigned-url": [], "cors-keyword": [],
            "pem-crossed-a": [], "pem-crossed-b": [],
            "pem-panel": ["private_key"], "pem-rsa": ["private_key"],
        }
        pages = {page.name: page for page in PAGES}
        scanner = Scanner()
        for name, labels in expected.items():
            with self.subTest(page=name):
                findings = await worker_findings(scanner, pages[name])
                self.assertCountEqual(findings, [(label, "[REDACTED]") for label in labels])

    async def test_benchmark_hits_agree_with_redacted_worker_on_every_page(self):
        scanner = Scanner(max_concurrent_requests=len(PAGES))
        for page in PAGES:
            with self.subTest(page=page.name):
                grouped = {}
                for _, span, label in observations(scanner, page):
                    grouped.setdefault(span, {})[label] = None
                expected = [(" + ".join(labels), "[REDACTED]") for labels in grouped.values()]
                self.assertCountEqual(await worker_findings(scanner, page), expected)

    def test_corpus_has_unique_names_and_unambiguous_target_spans(self):
        self.assertEqual(len({page.name for page in PAGES}), len(PAGES))
        for page in PAGES:
            for start, end, target in page.annotations:
                with self.subTest(page=page.name, start=start):
                    self.assertTrue(target.text)
                    self.assertEqual(page.html[start:end], target.text)
                    self.assertTrue(set(target.rules) <= set(RULES))
                    self.assertEqual(len(set(target.rules)), len(target.rules))

    def test_identical_page_content_can_have_different_owner_labels(self):
        pages = {page.name: page for page in PAGES}
        self.assertEqual(pages["assignment-guide"].html, pages["inline-config"].html)
        actual, shape, review = measure()
        self.assertLessEqual(review, shape)
        for name, count in (("inline-config", 1), ("assignment-guide", 0)):
            selected = Counter({key: n for key, n in actual.items() if key[1] == name})
            self.assertEqual((selected & shape).total(), 1)
            self.assertEqual((selected & review).total(), count)

    def test_duplicate_and_missing_positions_do_not_cancel_in_score(self):
        first = ("jwt", "sample", 10, 20)
        second = ("jwt", "sample", 30, 40)
        output = StringIO()
        with redirect_stdout(output):
            print_score("fixture", Counter([first, first]), Counter([first, second]))
        lines = [line.split() for line in output.getvalue().splitlines()]
        self.assertIn(["jwt", "1", "1", "1", "50.0%", "50.0%"], lines)
        self.assertIn(["FP:", "sample@10:20", "FN:", "sample@30:40"], lines)
        self.assertIn(["assignment", "0", "0", "0", "n/a", "n/a"], lines)
