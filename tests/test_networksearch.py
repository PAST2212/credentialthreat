import subprocess
import sys
import unittest
from pathlib import Path

import tldextract
from bs4 import BeautifulSoup

from credentialthreat.core.networksearch import ScanerNetworkResources
from http_doubles import response, session_returning


PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
PAGE = "https://www.example.com/p/1"
ROOT = Path(__file__).resolve().parents[1]


class ImportTests(unittest.TestCase):
    def test_each_scanner_module_imports_in_a_fresh_interpreter(self):
        for module in ("networksearch", "credentialsearch", "internallinksearch", "utils"):
            with self.subTest(module=module):
                result = subprocess.run([sys.executable, "-c", f"import credentialthreat.core.{module}"],
                                        cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr[-300:])


def extracted(markup, attr):
    tag = BeautifulSoup(markup, "html.parser").find()
    return [item.script_url for item in ScanerNetworkResources()._extract_url(tag, attr, PAGE, ["example.com"], PSL)]


class RedirectedPageTests(unittest.IsolatedAsyncioTestCase):
    async def test_resources_resolve_against_the_final_page(self):
        session = session_returning(
            response(301, "", {"Location": "/de/"}),
            response(200, '<script src="js/app.js"></script>', {"Content-Type": "text/html"}),
        )
        scanner = ScanerNetworkResources(scope=["example.com"])
        found = await scanner._fetch_network_sources("https://www.example.com/", ["example.com"], PSL, {}, session)
        self.assertEqual([(item.origin_url, item.script_url) for item in found], [
            ("https://www.example.com/de/", "https://www.example.com/de/"),
            ("https://www.example.com/de/", "https://www.example.com/de/js/app.js"),
        ])


class ResourceExtractionTests(unittest.TestCase):
    def test_resource_references_resolve_to_their_real_location(self):
        cases = {
            ('<script src="//static.example.com/js/app.js"></script>', "src"): ["https://static.example.com/js/app.js"],
            ('<script src="/js/app.js#v2"></script>', "src"): ["https://www.example.com/js/app.js"],
            ('<script src="https:\\/\\/www.example.com\\/js\\/a.js"></script>', "src"): ["https://www.example.com/js/a.js"],
            ('<script src="js/rel.js"></script>', "src"): ["https://www.example.com/p/js/rel.js"],
        }
        for (markup, attr), expected in cases.items():
            with self.subTest(markup=markup):
                self.assertEqual(extracted(markup, attr), expected)

    def test_binary_and_out_of_scope_references_are_dropped(self):
        for markup, attr in (('<link href="/img/logo.png">', "href"),
                             ('<link href="//cdn.other.invalid/a.js">', "href"),
                             ('<link href="mailto:a@example.com">', "href")):
            with self.subTest(markup=markup):
                self.assertEqual(extracted(markup, attr), [])


if __name__ == "__main__":
    unittest.main()
