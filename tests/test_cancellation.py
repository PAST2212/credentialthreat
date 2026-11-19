import asyncio
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch


CLI = runpy.run_path(str(Path(__file__).resolve().parents[1] / "credentialthreat.py"))


class RequestCancellationTests(unittest.IsolatedAsyncioTestCase):
    async def check_requests_stop(self, scanner, request_method, args):
        started = asyncio.Event()
        release = asyncio.Event()
        requests = []
        stopped = []

        async def blocked_request(item, *unused):
            requests.append(item)
            if len(requests) == 2:
                started.set()
            try:
                await release.wait()
            finally:
                stopped.append(item)

        with patch.object(scanner, request_method, side_effect=blocked_request):
            scan = asyncio.create_task(scanner.get_results(*args))
            try:
                await asyncio.wait_for(started.wait(), 2)
                await asyncio.wait_for(scanner.cancellation_manager.cancel_all(), 2)
                self.assertCountEqual(stopped, requests)
                await asyncio.wait_for(asyncio.shield(scan), 2)
                self.assertEqual(len(requests), 2, "A later batch started during cancellation")
            finally:
                release.set()
                await scan

    async def check_slow_request_does_not_hold_back_the_rest(self, scanner, args, name):
        release = asyncio.Event()
        finished = []

        async def request(item, *unused):
            if name(item) == "slow":
                await release.wait()
            finished.append(name(item))
            if len(finished) == 3:
                release.set()

        with patch.object(scanner, "_get_request", side_effect=request):
            await asyncio.wait_for(scanner.get_results(*args), 2)
        self.assertEqual(finished, ["a", "b", "c", "slow"])

    async def test_slow_page_does_not_hold_back_later_pages(self):
        urls = [f"https://test.invalid/{path}" for path in ("slow", "a", "b", "c")]
        await self.check_slow_request_does_not_hold_back_the_rest(
            CLI["ScanerNetworkResources"](window_size=2), (urls, ["test.invalid"], None), lambda url: url.rsplit("/", 1)[1])

    async def test_slow_resource_does_not_hold_back_later_resources(self):
        pairs = [("https://test.invalid/", f"https://test.invalid/{path}") for path in ("slow", "a", "b", "c")]
        await self.check_slow_request_does_not_hold_back_the_rest(
            CLI["ScanerCredentials"](window_size=2), (pairs,), lambda pair: pair[1].rsplit("/", 1)[1])

    async def test_slow_host_does_not_hold_back_later_hosts(self):
        hosts = [f"{name}.test.invalid" for name in ("slow", "a", "b", "c")]
        await self.check_slow_request_does_not_hold_back_the_rest(
            CLI["ScanerInternalLinks"](window_size=2), (hosts, None), lambda url: url.split("//")[1].split(".")[0])

    async def test_network_requests_stop_before_cancel_returns(self):
        scanner = CLI["ScanerNetworkResources"](window_size=2)
        urls = [f"https://test.invalid/{path}" for path in ("a", "b", "c")]
        await self.check_requests_stop(scanner, "_get_request", (urls, ["test.invalid"], None))

    async def test_credential_requests_stop_before_cancel_returns(self):
        scanner = CLI["ScanerCredentials"](window_size=2)
        await self.check_requests_stop(scanner, "_get_request", ([("a", "a"), ("b", "b"), ("c", "c")],))
