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
        found, _ = await scanner._fetch_network_sources("https://www.example.com/", ["example.com"], PSL, {}, session)
        self.assertEqual([(item.origin_url, item.script_url) for item in found], [
            ("https://www.example.com/de/", "https://www.example.com/de/js/app.js"),
        ])
        self.assertEqual(scanner.pages, {"https://www.example.com/", "https://www.example.com/de/"})


class PageCandidateTests(unittest.IsolatedAsyncioTestCase):
    async def test_page_text_is_matched_once_and_reported_redacted(self):
        marker = "PRIVATEFIXTUREONLY"
        page = PAGE + "?session=" + marker
        session = session_returning(response(
            200, f'<script src="/app.js"></script><script>var api_key = "{marker}";</script>',
            {"Content-Type": "text/html"}))
        scanner = ScanerNetworkResources(scope=["example.com"])
        resources, candidates = await scanner._fetch_network_sources(page, ["example.com"], PSL, {}, session)
        self.assertEqual(session.get.call_count, 1)
        self.assertEqual([item.script_url for item in resources], ["https://www.example.com/app.js"])
        self.assertEqual(candidates, [("https://www.example.com", "https://www.example.com",
                                       [("api_key", "[REDACTED]")])])
        self.assertNotIn(marker, str(candidates))
        self.assertEqual(scanner.pages, {page})
        self.assertEqual(dict(scanner.outcomes), {"ok": 1})

    async def test_inline_module_imports_are_collected(self):
        session = session_returning(response(200, (
            '<script type="module">import{a}from"./js/m.js";import("/lazy.js");'
            'import"https://static.example.com/s.js";import x from "react";</script>'),
            {"Content-Type": "text/html"}))
        scanner = ScanerNetworkResources(scope=["example.com"])
        found, _ = await scanner._fetch_network_sources("https://www.example.com/de/", ["example.com"], PSL, {}, session)
        self.assertCountEqual([item.script_url for item in found], [
            "https://www.example.com/de/js/m.js", "https://www.example.com/lazy.js", "https://static.example.com/s.js",
        ])

    async def test_bot_challenge_page_contributes_no_resources(self):
        session = session_returning(response(
            400, '<script src="/149e/ips.js?KP_UIDz=PRIVATEFIXTUREONLY"></script>',
            {"Content-Type": "text/html", "x-kpsdk-ct": "token"}))
        scanner = ScanerNetworkResources(scope=["example.com"])
        self.assertEqual(await scanner._fetch_network_sources(PAGE, ["example.com"], PSL, {}, session), ([], []))
        self.assertEqual(scanner.pages, {PAGE})
        self.assertEqual(dict(scanner.outcomes), {"bot challenge": 1})

    async def test_unreadable_page_is_recorded_without_candidates(self):
        session = session_returning(response(200, "", {"Content-Type": "application/pdf"}))
        scanner = ScanerNetworkResources(scope=["example.com"])
        self.assertEqual(await scanner._fetch_network_sources(PAGE, ["example.com"], PSL, {}, session), ([], []))
        self.assertEqual(scanner.pages, {PAGE})


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

    def test_link_elements_count_only_when_the_browser_loads_them(self):
        # A production help page listed 108 translations of itself as <link rel="alternate" hreflang>, next to three
        # stylesheets. Following them sent 80,643 HTML pages, 88% of all requests, to the resource stage.
        html = ('<link rel="alternate" hreflang="de-de" href="/de-de/p/1">'
                '<link rel="alternate" hreflang="fr-fr" href="/fr-fr/p/1">'
                '<link rel="alternate" type="application/rss+xml" href="/feed.xml">'
                '<link rel="canonical" href="/p/1-canonical"><link rel="next" href="/p/2">'
                '<link rel="preconnect" href="https://static.example.com"><link rel="dns-prefetch" href="//api.example.com">'
                '<link rel="stylesheet" href="/css/site.css"><link rel="preload" as="script" href="/js/boot.js">'
                '<link rel="modulepreload" href="/js/module.mjs"><link rel="prefetch" href="/js/later.js">'
                '<link rel="manifest" href="/site.webmanifest"><link rel="Stylesheet Preload" href="/css/two.css">')
        resources, _ = ScanerNetworkResources().scan_page(PAGE, html, BeautifulSoup(html, "html.parser"), ["example.com"])
        self.assertCountEqual([item.script_url for item in resources], [
            "https://www.example.com/css/site.css", "https://www.example.com/js/boot.js",
            "https://www.example.com/js/module.mjs", "https://www.example.com/js/later.js",
            "https://www.example.com/site.webmanifest", "https://www.example.com/css/two.css"])

    def test_binary_and_out_of_scope_references_are_dropped(self):
        for markup, attr in (('<link href="/img/logo.png">', "href"),
                             ('<link href="//cdn.other.invalid/a.js">', "href"),
                             ('<link href="mailto:a@example.com">', "href")):
            with self.subTest(markup=markup):
                self.assertEqual(extracted(markup, attr), [])


if __name__ == "__main__":
    unittest.main()
