import unittest

from credentialthreat.core.website import canonical_url, is_binary_url


class CanonicalUrlTests(unittest.TestCase):
    def test_fetchable_variants_of_one_page_share_one_form(self):
        cases = {
            "https://Shop.Example.com/a#reviews": "https://shop.example.com/a",
            "https://shop.example.com": "https://shop.example.com/",
            "https://shop.example.com/#top": "https://shop.example.com/",
            "HTTPS://SHOP.EXAMPLE.COM/Upper": "https://shop.example.com/Upper",
            "https://shop.example.com:443/x": "https://shop.example.com/x",
            "https://shop.example.com/p?q=1#r": "https://shop.example.com/p?q=1",
            "http://shop.example.com/plain": "http://shop.example.com/plain",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(canonical_url(raw), expected)

    def test_non_web_and_credential_bearing_references_are_rejected(self):
        for raw in ("mailto:info@example.com", "tel:+49123", "javascript:void(0)",
                    "data:text/html,hi", "//shop.example.com/x", "/relative/path",
                    "https://user:secret@shop.example.com/", "ftp://shop.example.com/x", ""):
            with self.subTest(raw=raw):
                self.assertIsNone(canonical_url(raw))


class BinaryUrlTests(unittest.TestCase):
    def test_binary_file_extensions_in_the_path_are_detected(self):
        for url in ("https://h.example.com/a.png", "https://h.example.com/doc.PDF",
                    "https://h.example.com/v.mp4?download=1", "https://h.example.com/archive.tar.gz",
                    "https://h.example.com/fonts/x.woff2#iefix"):
            with self.subTest(url=url):
                self.assertTrue(is_binary_url(url))

    def test_text_resources_and_lookalike_hosts_are_not_binary(self):
        for url in ("https://h.example.com/app.js", "https://h.example.com/a.png.js",
                    "https://img.example.app/index.html", "https://h.example.com/page",
                    "https://h.example.com/files/", "https://h.example.com/?file=a.pdf"):
            with self.subTest(url=url):
                self.assertFalse(is_binary_url(url))


if __name__ == "__main__":
    unittest.main()
