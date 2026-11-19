from pathlib import Path
import runpy
import ssl
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import aiohttp
import tldextract
from aiohttp import web
from aiohttp.test_utils import TestServer
from bs4 import BeautifulSoup

from http_doubles import response as http_response


CLI = runpy.run_path(str(Path(__file__).resolve().parents[1] / "credentialthreat.py"))
SITE = "https://docs.example.com"
PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def session_returning(status, body, headers=None):
    response = http_response(status, body, headers)
    manager = MagicMock()
    manager.__aenter__.return_value = response
    return Mock(get=Mock(return_value=manager)), response


class WebsiteSafetyTests(unittest.IsolatedAsyncioTestCase):
    def fetchers(self):
        return [
            (CLI["ScanerInternalLinks"](), SITE),
            (CLI["ScanerNetworkResources"](), SITE),
            (CLI["ScanerCredentials"](), (SITE, SITE)),
        ]

    async def test_website_fetches_skip_redirects_without_reading_the_body(self):
        for scanner, arg in self.fetchers():
            for status in (301, 302, 303, 304, 307, 308):
                with self.subTest(phase=type(scanner).__name__, status=status):
                    session, response = session_returning(status, "unused", {"Location": "https://other.invalid/"})
                    result = await scanner._get_request(arg, {}, session)
                    self.assertIsNone(result)
                    self.assertIs(session.get.call_args.kwargs["allow_redirects"], False)
                    self.assertEqual(response.content.reads, 0)
                    session.get.assert_called_once()

    async def test_certificate_failure_does_not_trigger_an_insecure_retry(self):
        for scanner, arg in self.fetchers():
            with self.subTest(phase=type(scanner).__name__):
                session, response = session_returning(200, "unused")
                session.get.return_value.__aenter__.side_effect = aiohttp.ClientConnectorCertificateError(
                    Mock(), ssl.CertificateError("synthetic certificate mismatch"))
                self.assertIsNone(await scanner._get_request(arg, {}, session))
                session.get.assert_called_once()
                self.assertEqual(response.content.reads, 0)

    async def test_each_website_session_verifies_the_server_certificate(self):
        real_session = aiohttp.ClientSession
        contexts = []

        def record_session(**kwargs):
            session = real_session(**kwargs)
            request = Mock(ssl=True)
            contexts.append(session.connector._get_ssl_context(request))
            return session

        scanners = [
            CLI["ScanerInternalLinks"]().process_internal_links([], PSL),
            CLI["ScanerNetworkResources"]().process_network_sources([], ["example.com"], PSL),
            CLI["ScanerCredentials"]().process_credentials([]),
        ]
        with patch.object(aiohttp, "ClientSession", side_effect=record_session):
            for scan in scanners:
                await scan
        self.assertEqual(len(contexts), 3)
        for context in contexts:
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)

    async def test_each_website_session_limits_connections_per_host_to_the_worker_share(self):
        real_session = aiohttp.ClientSession
        limits = []

        def record_session(**kwargs):
            session = real_session(**kwargs)
            limits.append(session.connector.limit_per_host)
            return session

        scans = [
            CLI["ScanerInternalLinks"](host_connections=5).process_internal_links([], PSL),
            CLI["ScanerNetworkResources"](host_connections=5).process_network_sources([], ["example.com"], PSL),
            CLI["ScanerCredentials"](host_connections=5).process_credentials([]),
        ]
        with patch.object(aiohttp, "ClientSession", side_effect=record_session):
            for scan in scans:
                await scan
        self.assertEqual(limits, [5, 5, 5])

    async def test_redirect_destination_receives_zero_requests_over_loopback(self):
        arrivals = []

        async def destination(request):
            arrivals.append(request.path)
            return web.Response(text="test fixture")

        sink = web.Application()
        sink.router.add_get("/destination", destination)
        async with TestServer(sink) as sink_server:
            async def redirect(request):
                return web.Response(status=302, headers={"Location": str(sink_server.make_url("/destination"))})

            source = web.Application()
            source.router.add_get("/", redirect)
            async with TestServer(source) as source_server, aiohttp.ClientSession() as session:
                url = str(source_server.make_url("/"))
                for scanner, arg in self.fetchers():
                    target = (url, url) if isinstance(arg, tuple) else url
                    with self.subTest(phase=type(scanner).__name__):
                        self.assertIsNone(await scanner._get_request(target, {}, session))
        self.assertEqual(arrivals, [])

    async def test_worker_returns_only_origins_and_redacted_candidate_labels(self):
        raw = "SYNTHETICFIXTUREONLY"
        url = SITE + "/private/" + raw + "?session=" + raw + "#" + raw
        session, _ = session_returning(200, f'api_key = "{raw}"; public_key = "DOCUMENTATIONEXAMPLE";')
        result = await CLI["ScanerCredentials"]()._get_request((url, url), {}, session)
        self.assertEqual(result, (SITE, SITE, [("api_key", "[REDACTED]"), ("public_key", "[REDACTED]")]))

    async def test_assignment_requires_the_same_opening_and_closing_quote(self):
        scanner = CLI["ScanerCredentials"]()
        for opening, closing in (('"', "'"), ("'", '"'), ('"', '"'), ("'", "'")):
            with self.subTest(opening=opening, closing=closing):
                session, _ = session_returning(200, f"api_key = {opening}FIXTUREONLY{closing};")
                result = await scanner._get_request((SITE, SITE), {}, session)
                if opening == closing:
                    self.assertEqual(result, (SITE, SITE, [("api_key", "[REDACTED]")]))
                else:
                    self.assertIsNone(result)

    async def test_two_rules_on_one_value_count_once_per_text_position(self):
        value = "AKIA" + "TEST" * 4
        scanner = CLI["ScanerCredentials"]()
        for occurrences in (1, 2):
            with self.subTest(occurrences=occurrences):
                session, _ = session_returning(200, f'api_key = "{value}";\n' * occurrences)
                result = await scanner._get_request((SITE, SITE), {}, session)
                self.assertEqual(result, (SITE, SITE, [("api_key + aws_keys", "[REDACTED]")] * occurrences))

    async def test_one_rule_can_still_report_multiple_distinct_values(self):
        session, _ = session_returning(200, 'api_key = "FIXTUREONE"; api_key = "FIXTURETWO";')
        result = await CLI["ScanerCredentials"]()._get_request((SITE, SITE), {}, session)
        self.assertEqual(result, (SITE, SITE, [("api_key", "[REDACTED]")] * 2))

    async def test_log_level_setting_alone_is_not_a_credential(self):
        for setting in ('app_log_level = "CRITICAL"', 'APP_LOG_LEVEL = "DEVELOPMENT"'):
            with self.subTest(setting=setting):
                session, _ = session_returning(200, setting)
                result = await CLI["ScanerCredentials"]()._get_request((SITE, SITE), {}, session)
                self.assertIsNone(result)

    async def test_request_failure_diagnostics_do_not_echo_url_or_exception_payload(self):
        marker = "PRIVATEFIXTUREONLY"
        for scanner, arg in self.fetchers():
            with self.subTest(phase=type(scanner).__name__):
                url = SITE + "/" + marker
                target = (url, url) if isinstance(arg, tuple) else url
                session = Mock()
                session.get.side_effect = RuntimeError(marker)
                with self.assertLogs(level="ERROR") as logs:
                    self.assertIsNone(await scanner._get_request(target, {}, session))
                self.assertNotIn(marker, " ".join(logs.output))
                self.assertIn("RuntimeError", " ".join(logs.output))

    async def test_out_of_scope_page_never_reaches_the_transport(self):
        scanner = CLI["ScanerNetworkResources"]()
        session, _ = session_returning(200, "<html></html>")
        result = await scanner._fetch_network_sources("https://example.com.other.invalid/",
                                                     ["example.com"], PSL, {}, session)
        self.assertEqual(result, ([], []))
        session.get.assert_not_called()

    async def test_resource_attributes_and_inline_references_respect_host_boundaries(self):
        scanner = CLI["ScanerNetworkResources"]()
        html = """<script src="/local.js"></script>
        <script src="https://example.com.other.invalid/bad.js"></script>
        <script>require("https://elsewhere.invalid/other.js")</script>"""
        with patch.object(scanner, "_get_request", new=AsyncMock(return_value=(SITE, html, BeautifulSoup(html, "html.parser")))):
            found, _ = await scanner._fetch_network_sources(SITE, ["example.com"], PSL, {}, Mock())
        self.assertEqual({item.script_url for item in found}, {SITE + "/local.js"})
