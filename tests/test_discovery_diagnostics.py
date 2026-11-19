from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import logging
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import aiohttp
from yarl import URL

from credentialthreat.core.subdomainsearch import SubdomainScanner
from credentialthreat.recon.crtsh import ScanerCrtsh
from credentialthreat.recon.dnsdumpster import ScanerDnsDumpster
from credentialthreat.recon.rapiddns import ScanerRapidDns
from credentialthreat.recon.subdomaincenter import ScanerSubdomainCenter


DOMAIN = "private-target.example"
MARKER = "PRIVATEFIXTUREONLY"
PROVIDERS = (("crt.sh", ScanerCrtsh), ("rapiddns", ScanerRapidDns))


@contextmanager
def capture_diagnostics():
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    logger = logging.getLogger()
    logger.addHandler(handler)
    try:
        with redirect_stdout(output), redirect_stderr(output):
            yield output
    finally:
        logger.removeHandler(handler)
        handler.close()


class DiscoveryDiagnosticTests(unittest.IsolatedAsyncioTestCase):
    def assert_private_diagnostic(self, output, provider, reason):
        self.assertNotIn(MARKER, output)
        self.assertNotIn(DOMAIN, output)
        self.assertIn(provider.lower(), output.lower())
        self.assertIn(reason, output)

    async def test_provider_errors_omit_request_urls_and_exception_text(self):
        request = Mock(real_url=URL(f"https://provider.invalid/path?fixture={MARKER}"))
        error = aiohttp.ClientResponseError(request, (), status=403, message=MARKER)
        session = Mock()
        session.get.side_effect = error
        calls = [(name, scanner().get_results([DOMAIN], session)) for name, scanner in PROVIDERS]
        calls.extend([
            ("dnsdumpster", ScanerDnsDumpster().get_results([DOMAIN], session)),
            ("subdomain", ScanerSubdomainCenter().get_results([DOMAIN], session)),
        ])
        for name, call in calls:
            with self.subTest(provider=name), capture_diagnostics() as output:
                await call
                self.assert_private_diagnostic(output.getvalue(), name, "ClientResponseError")
                self.assertIn("403", output.getvalue())

    async def test_status_messages_keep_http_code_and_omit_the_target(self):
        manager = MagicMock()
        manager.__aenter__.return_value = Mock(status=503)
        for name, scanner in PROVIDERS:
            with self.subTest(provider=name), capture_diagnostics() as output:
                session = Mock(get=Mock(return_value=manager))
                self.assertEqual(await scanner().get_results([DOMAIN], session), set())
                self.assert_private_diagnostic(output.getvalue(), name, "503")

    async def test_per_domain_failure_handlers_omit_exception_payloads(self):
        for name, scanner_type in PROVIDERS:
            scanner = scanner_type()
            failure = AsyncMock(side_effect=RuntimeError(MARKER))
            with self.subTest(provider=name), patch.object(scanner, "_scrape_subdomains", failure):
                with capture_diagnostics() as output:
                    self.assertEqual(await scanner.get_results([DOMAIN], Mock()), set())
                self.assert_private_diagnostic(output.getvalue(), name, "RuntimeError")

    async def test_discovery_coordinator_omits_exception_payloads(self):
        scanner = SubdomainScanner()
        with patch.object(scanner, "scan_with_rate_limit", new=AsyncMock(side_effect=RuntimeError(MARKER))):
            with capture_diagnostics() as output:
                await scanner.tasks_subdomains([DOMAIN])
        self.assert_private_diagnostic(output.getvalue(), "subdomain", "RuntimeError")
