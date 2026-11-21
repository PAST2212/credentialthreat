import unittest

import tldextract

from credentialthreat.core.internallinksearch import ScanerInternalLinks
from http_doubles import response, session_returning


PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


class RootPageTests(unittest.IsolatedAsyncioTestCase):
    async def test_redirected_root_yields_the_final_page_and_its_relative_links(self):
        session = session_returning(
            response(302, "", {"Location": "https://www.example.com/"}),
            response(301, "", {"Location": "/de/"}),
            response(200, '<a href="kontakt.html">Kontakt</a><a href="/files/a.pdf">PDF</a>'),
        )
        scanner = ScanerInternalLinks(scope=["example.com"])
        links = await scanner._fetch_internal_links("example.com", PSL, {}, session)
        self.assertEqual(links, {"https://www.example.com/de/", "https://www.example.com/de/kontakt.html"})
        self.assertEqual(scanner.outcomes["ok"], 1)

    async def test_unreachable_root_is_reported_in_the_outcomes(self):
        session = session_returning(TimeoutError(), TimeoutError(), TimeoutError())
        scanner = ScanerInternalLinks(scope=["example.com"])
        with unittest.mock.patch("asyncio.sleep"):
            self.assertEqual(await scanner._fetch_internal_links("example.com", PSL, {}, session), set())
        self.assertEqual(dict(scanner.outcomes), {"timeout": 1})
        self.assertEqual(scanner.pages, {"https://example.com/"})  # requested, so the page stage skips it

    async def test_start_page_is_scanned_like_any_other_page(self):
        # The page stage does not request start pages again, so their resources and candidates are kept here.
        session = session_returning(
            response(302, "", {"Location": "https://www.example.com/de/"}),
            response(200, '<a href="kontakt.html">Kontakt</a><script src="app.js"></script>'
                          '<script>api_key = "SYNTHETICFIXTURE";</script>'),
        )
        scanner = ScanerInternalLinks(scope=["example.com"])
        await scanner._fetch_internal_links("example.com", PSL, {}, session)
        page = "https://www.example.com/de/"
        self.assertEqual(scanner.pages, {"https://example.com/", page})
        self.assertEqual([(item.origin_url, item.script_url) for item in scanner.resources], [(page, page + "app.js")])
        self.assertEqual(scanner.candidates,
                         [("https://www.example.com", "https://www.example.com", [("api_key", "[REDACTED]")])])


class LinkResolutionTests(unittest.TestCase):
    def resolve(self, href, page="https://shop.example.com/"):
        return ScanerInternalLinks()._process_link(href, page)

    def test_links_resolve_against_the_fetched_page_without_fragments(self):
        cases = {
            ("/", "https://shop.example.com/"): "https://shop.example.com/",
            ("#top", "https://shop.example.com/"): "https://shop.example.com/",
            ("/p/5#reviews", "https://shop.example.com/"): "https://shop.example.com/p/5",
            ("//shop.example.com/pr", "https://shop.example.com/"): "https://shop.example.com/pr",
            ("HTTPS://SHOP.EXAMPLE.COM/Upper", "https://shop.example.com/"): "https://shop.example.com/Upper",
            ("kontakt.html", "https://shop.example.com/de/"): "https://shop.example.com/de/kontakt.html",
            ("../impressum", "https://shop.example.com/de/start"): "https://shop.example.com/impressum",
            (" /p/6 ", "https://shop.example.com/"): "https://shop.example.com/p/6",
            ("/a?x=1&amp;y=2", "https://shop.example.com/"): "https://shop.example.com/a?x=1&y=2",
        }
        for (href, page), expected in cases.items():
            with self.subTest(href=href, page=page):
                self.assertEqual(self.resolve(href, page), expected)

    def test_non_page_references_are_not_returned(self):
        for href in ("tel:+49123", "mailto:info@example.com", "data:text/html,hi",
                     "javascript:void(0)", "/files/manual.pdf", "//shop.example.com/logo.PNG", ""):
            with self.subTest(href=href):
                self.assertIsNone(self.resolve(href))


if __name__ == "__main__":
    unittest.main()
