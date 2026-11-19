from pathlib import Path
import runpy
import socket
import unittest
from unittest.mock import AsyncMock, Mock, patch

import aiohttp

from credentialthreat.core.subdomainsearch import SubdomainScanner
from credentialthreat.core.website import SUFFIXES
from credentialthreat.recon.crtsh import ScanerCrtsh


CLI = runpy.run_path(str(Path(__file__).resolve().parents[1] / "credentialthreat.py"))
HOST = "fixture.example.com"
URL = f"https://{HOST}/"


def answers(*addresses):
    return [
        dict(hostname=HOST, host=ip, port=443,
             family=socket.AF_INET6 if ":" in ip else socket.AF_INET, proto=0, flags=0)
        for ip in addresses
    ]


class DestinationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.resolver = Mock(resolve=AsyncMock(return_value=answers("127.0.0.1")), close=AsyncMock())
        self.enterContext(patch("aiohttp.connector.DefaultResolver", return_value=self.resolver))
        self.dial = self.enterContext(patch("aiohttp.connector.aiohappyeyeballs.start_connection",
                                            new=AsyncMock(side_effect=OSError("offline socket boundary"))))

    async def test_discovery_distinguishes_a_rejected_address_from_failed_dns(self):
        async with SubdomainScanner() as scanner:
            session = await scanner.session
            adapter = ScanerCrtsh()
            denied, = await adapter.get_report([HOST], session)
            session.connector.clear_dns_cache()
            self.resolver.resolve.side_effect = socket.gaierror(socket.EAI_NONAME, "offline NXDOMAIN")
            missing, = await adapter.get_report([HOST], session)
        self.assertEqual((missing.state, missing.reason), ("error", "DNS"))
        self.assertEqual((denied.state, denied.reason), ("error", "destination blocked"))
        self.dial.assert_not_awaited()

    async def test_every_scan_stage_blocks_private_dns_before_connecting(self):
        async def try_get(session):
            with self.assertRaises(aiohttp.ClientConnectorError):
                await session.get(URL)

        async def discovery():
            async with SubdomainScanner() as scanner:
                await try_get(await scanner.session)

        stages = {
            "links": CLI["ScanerInternalLinks"]().process_internal_links([HOST], SUFFIXES),
            "resources": CLI["ScanerNetworkResources"]().process_network_sources([URL], ["example.com"], SUFFIXES),
            "matches": CLI["ScanerCredentials"]().process_credentials([(URL, URL)]),
            "discovery": discovery(),
        }
        for name, stage in stages.items():
            with self.subTest(stage=name):
                self.dial.reset_mock()
                self.resolver.resolve.reset_mock()
                await stage
                self.resolver.resolve.assert_awaited_once()
                self.dial.assert_not_awaited()

    async def test_nonpublic_and_malformed_answers_are_blocked_as_a_set(self):
        denied = (
            "127.0.0.1", "10.0.0.1", "169.254.1.1", "100.64.0.1", "224.0.0.1",
            "0.0.0.0", "192.0.0.8", "192.88.99.1", "192.0.2.1", "::1", "fc00::1",
            "fe80::1", "fec0::1", "ff02::1", "::ffff:127.0.0.1", "64:ff9b::1",
            "2002::1", "2001::1", "2001:db8::1", "3fff::1",
            "2606:4700:4700::1111%1", "unresolved.invalid",
        )
        async with SubdomainScanner() as scanner:
            session = await scanner.session
            for address in denied:
                with self.subTest(address=address):
                    self.dial.reset_mock()
                    session.connector.clear_dns_cache()
                    self.resolver.resolve.return_value = answers("1.1.1.1", address)
                    with self.assertRaises(aiohttp.ClientConnectorError):
                        await session.get(URL)
                    self.dial.assert_not_awaited()

    async def test_literal_addresses_cannot_bypass_the_destination_check(self):
        async with SubdomainScanner() as scanner:
            session = await scanner.session
            for authority in ("127.0.0.1", "[::1]"):
                with self.subTest(authority=authority):
                    with self.assertRaises(aiohttp.ClientConnectorError):
                        await session.get(f"https://{authority}/")
                    self.dial.assert_not_awaited()
        self.resolver.resolve.assert_not_awaited()

    async def test_only_checked_addresses_reach_the_dialer_after_dns_changes(self):
        # Intercept accepted attempts before socket creation, without triggering HTTP retries.
        self.dial.side_effect = RuntimeError("accepted by connector")
        public = ("1.1.1.1", "2606:4700:4700::1111")
        self.resolver.resolve.side_effect = [answers(*public), answers("10.0.0.1")]
        async with SubdomainScanner() as scanner:
            session = await scanner.session
            with self.assertRaisesRegex(RuntimeError, "accepted by connector"):
                await session.get(URL)
            self.dial.assert_awaited_once()
            sent = self.dial.await_args.kwargs["addr_infos"]
            self.assertEqual([addr[4][:2] for addr in sent], [(ip, 443) for ip in public])
            session.connector.clear_dns_cache()
            for _ in range(2):  # also exercise a cache hit on the denied answer
                with self.assertRaises(aiohttp.ClientConnectorError):
                    await session.get(URL)
        self.assertEqual(self.resolver.resolve.await_count, 2)
        self.dial.assert_awaited_once()
