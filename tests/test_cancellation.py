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

    async def test_network_requests_stop_before_cancel_returns(self):
        scanner = CLI["ScanerNetworkResources"](batch_size=2)
        urls = [f"https://test.invalid/{path}" for path in ("a", "b", "c")]
        await self.check_requests_stop(scanner, "_get_request", (urls, ["test.invalid"], None))

    async def test_credential_requests_stop_before_cancel_returns(self):
        scanner = CLI["ScanerCredentials"](batch_size=2)
        await self.check_requests_stop(scanner, "_get_request", ([("a", "a"), ("b", "b"), ("c", "c")],))
