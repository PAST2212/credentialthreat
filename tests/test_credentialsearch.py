import asyncio
import unittest
from unittest.mock import MagicMock, Mock, patch

from credentialthreat.core.credentialsearch import ScanerCredentials
from credentialthreat.core.fetch import HostPacer
from credentialthreat.core.internallinksearch import ScanerInternalLinks
from credentialthreat.core.networksearch import ScanerNetworkResources
from http_doubles import FakeClock, response, session_returning


SITE = "https://docs.example.com"


class ThrottledResourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_throttled_resource_is_scanned_after_retry(self):
        session = session_returning(response(429, "Too Many Requests", {"Retry-After": "1"}),
                                    response(200, 'api_key = "FIXTUREONLYVALUE";'))
        scanner = ScanerCredentials(scope=["example.com"])
        clock = FakeClock()
        scanner.pacer = HostPacer(clock=clock.now, sleep=clock.sleep)
        result = await scanner._get_request((SITE, SITE + "/app.js"), {}, session)
        self.assertEqual(result, (SITE, SITE, [("api_key", "[REDACTED]")]))
        self.assertEqual(dict(scanner.outcomes), {"ok": 1})

    async def test_resource_that_stays_throttled_is_counted_as_skipped(self):
        session = session_returning(*[response(429, 'api_key = "NOTCONTENTFIXTURE";') for _ in range(3)])
        scanner = ScanerCredentials(scope=["example.com"])
        clock = FakeClock()
        scanner.pacer = HostPacer(clock=clock.now, sleep=clock.sleep)
        self.assertIsNone(await scanner._get_request((SITE, SITE + "/app.js"), {}, session))
        self.assertEqual(dict(scanner.outcomes), {"HTTP 429": 1})


class HostPausePerWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_throttled_host_also_pauses_the_workers_next_request_to_it(self):
        scanners = (
            (ScanerCredentials(scope=["example.com"]), lambda url: (SITE, url)),
            (ScanerNetworkResources(scope=["example.com"]), lambda url: url),
            (ScanerInternalLinks(scope=["example.com"]), lambda url: url),
        )
        for scanner, argument in scanners:
            with self.subTest(scanner=type(scanner).__name__):
                clock = FakeClock()
                scanner.pacer = HostPacer(rate=1000, clock=clock.now, sleep=clock.sleep)
                replies = iter([response(429, "", {"Retry-After": "5"}) for _ in range(3)] + [response(200, "ok")])
                sent_at = []

                def get(url, **kwargs):
                    sent_at.append(clock.now())
                    manager = MagicMock()
                    manager.__aenter__.return_value = next(replies)
                    return manager

                session = Mock(get=get)
                with patch("asyncio.sleep", new=clock.sleep):
                    self.assertIsNone(await scanner._get_request(argument(SITE + "/a.js"), {}, session))
                    await scanner._get_request(argument(SITE + "/b.js"), {}, session)
                self.assertGreaterEqual(sent_at[3] - sent_at[2], 5.0)


class HostShareTests(unittest.IsolatedAsyncioTestCase):
    async def test_worker_never_sends_more_than_its_host_share_at_once(self):
        scanners = (
            (ScanerCredentials(max_concurrent_requests=1000, host_connections=2), lambda url: (SITE, url)),
            (ScanerNetworkResources(max_concurrent_requests=1000, host_connections=2), lambda url: url),
            (ScanerInternalLinks(max_concurrent_requests=1000, host_connections=2), lambda url: url),
        )
        for scanner, argument in scanners:
            with self.subTest(scanner=type(scanner).__name__):
                active = peak = 0

                def get(url, **kwargs):
                    async def enter(*args):
                        nonlocal active, peak
                        active += 1
                        peak = max(peak, active)
                        await asyncio.sleep(0.05)
                        active -= 1
                        return response(200, "ok")
                    manager = MagicMock()
                    manager.__aenter__.side_effect = enter
                    return manager

                session = Mock(get=get)
                urls = [argument(f"{SITE}/{index}.js") for index in range(8)]
                await scanner.cancellation_manager.run_window(urls, lambda url: scanner._get_request(url, {}, session), 8)
                self.assertEqual(peak, 2)


if __name__ == "__main__":
    unittest.main()
