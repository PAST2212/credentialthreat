import asyncio
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
from multiprocessing.pool import ThreadPool
from pathlib import Path
import runpy
import socket
import sys
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import urlsplit

import aiohttp

from credentialthreat.core.subdomainsearch import SubdomainScanner
from credentialthreat.recon.crtsh import ScanerCrtsh
from credentialthreat.recon.rapiddns import ScanerRapidDns


CLI = runpy.run_path(str(Path(__file__).resolve().parents[1] / "credentialthreat.py"))
HOST = "private-fixture.example"
CHILD = "docs." + HOST
PRIVATE = "PRIVATEFIXTUREONLY"
TABLE_HEAD = '<table id="table"><thead><tr><th>#</th><th>Domain</th><th>Address</th><th>Type</th><th>Date</th></tr></thead>'
TABLE_END = "</tbody></table>"
EMPTY = {
    "crt.sh": "[]",
    "RapidDNS": TABLE_HEAD + "<tbody>" + TABLE_END,
}
HITS = {
    "crt.sh": json.dumps([{"name_value": "*." + CHILD}]),
    "RapidDNS": TABLE_HEAD + "<tbody><tr><th>1</th><td>" + CHILD + "</td><td>192.0.2.1</td><td>A</td><td>2025</td></tr>" + TABLE_END,
}
TYPES = {
    "crt.sh": ScanerCrtsh,
    "RapidDNS": ScanerRapidDns,
}


class FixtureResponse:
    def __init__(self, body, status=200):
        self.body = body
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def text(self):
        return self.body


def dns_failure():
    return aiohttp.ClientConnectorDNSError(Mock(), socket.gaierror(-2, PRIVATE))


class ProviderResultsTests(unittest.IsolatedAsyncioTestCase):
    async def query(self, name, body="", status=200, error=None):
        session = Mock()
        session.get.side_effect = error
        session.get.return_value = FixtureResponse(body, status)
        scanner = TYPES[name]()
        with patch("asyncio.sleep", new=AsyncMock()):
            results = await scanner.get_report([HOST], session)
        result, = results
        self.assertEqual((result.provider, result.domain), (name, HOST))
        # A server error gets exactly one more attempt.
        self.assertEqual(session.get.call_count, 2 if status >= 500 else 1)
        return result

    async def test_server_error_is_retried_once_after_the_providers_pause(self):
        # crt.sh publishes 5 requests per minute, RapidDNS 30: the pause keeps the retry within them.
        for name, minimum_pause in (("crt.sh", 12), ("RapidDNS", 2)):
            with self.subTest(provider=name):
                session = Mock()
                session.get.side_effect = [FixtureResponse(PRIVATE, 502), FixtureResponse(HITS[name])]
                with patch("asyncio.sleep", new=AsyncMock()) as pause:
                    result, = await TYPES[name]().get_report([HOST], session)
                self.assertEqual((result.state, result.values), ("hits", {CHILD}))
                self.assertEqual(session.get.call_count, 2)
                self.assertGreaterEqual(pause.await_args.args[0], minimum_pause)

    async def test_client_errors_are_not_retried(self):
        for name in TYPES:
            for status in (403, 404, 429):
                with self.subTest(provider=name, status=status):
                    session = Mock()
                    session.get.return_value = FixtureResponse(PRIVATE, status)
                    with patch("asyncio.sleep", new=AsyncMock()) as pause:
                        result, = await TYPES[name]().get_report([HOST], session)
                    self.assertEqual(result.reason, f"HTTP {status}")
                    session.get.assert_called_once()
                    pause.assert_not_awaited()

    async def test_hits_and_confirmed_empty_for_all_providers(self):
        for name in TYPES:
            with self.subTest(provider=name):
                hit = await self.query(name, HITS[name])
                self.assertEqual((hit.state, hit.records, hit.reason), ("hits", 1, None))
                self.assertEqual(hit.values, {CHILD})
                empty = await self.query(name, EMPTY[name])
                self.assertEqual((empty.state, empty.records, empty.values, empty.reason), ("empty", 0, set(), None))

    async def test_dns_timeout_http_and_invalid_bodies_are_errors(self):
        for name in TYPES:
            for reason, body, status, error in (
                ("DNS", "", 200, dns_failure()), ("timeout", "", 200, asyncio.TimeoutError(PRIVATE)),
                ("HTTP 503", PRIVATE, 503, None), ("unexpected format", "<p>sign in</p>", 200, None),
                ("unexpected format", "", 200, None),
            ):
                with self.subTest(provider=name, reason=reason, body=body):
                    result = await self.query(name, body, status, error)
                    self.assertEqual((result.state, result.reason, result.records, result.values),
                                     ("error", reason, None, set()))

    async def test_malformed_success_cannot_yield_a_partial_hit_or_confirmed_empty(self):
        for name, bodies in {
            "crt.sh": ["{}", '[{"name_value":" "}]', json.dumps([{"name_value": CHILD}, {"different": PRIVATE}])],
            "RapidDNS": ['<table id="table"></table>', TABLE_HEAD + '<tbody><tr><td>challenge</td></tr>' + TABLE_END],
        }.items():
            for body in bodies:
                with self.subTest(provider=name, body=body):
                    result = await self.query(name, body)
                    self.assertEqual((result.state, result.reason, result.values), ("error", "unexpected format", set()))

    async def test_nonempty_out_of_scope_data_is_not_a_confirmed_empty_response(self):
        for name, body in HITS.items():
            with self.subTest(provider=name):
                result = await self.query(name, body.replace(CHILD, "other.example"))
                self.assertEqual((result.state, result.records, result.values), ("filtered", 1, set()))

    async def test_provider_exceptions_leave_other_queries_intact(self):
        scanner = TYPES["crt.sh"]()
        session = Mock()
        session.get.side_effect = [dns_failure(), FixtureResponse(EMPTY["crt.sh"]), FixtureResponse(HITS["crt.sh"])]
        results = await scanner.get_report(["unavailable.example", "empty.example", HOST], session)
        self.assertEqual([q.state for q in results], ["error", "empty", "hits"])
        async with SubdomainScanner() as coordinator:
            async def provider_batch(scanner, domains, service):
                if service == "crtsh":
                    return results
                raise RuntimeError(PRIVATE)
            with patch.object(coordinator, "scan_with_rate_limit", new=provider_batch):
                combined = await coordinator.tasks_subdomains(["unavailable.example", "empty.example", HOST])
        self.assertEqual(len(combined), 6)
        self.assertEqual([q.values for q in combined if q.state == "hits"], [{CHILD}])
        self.assertEqual(sum(q.state == "error" for q in combined), 4)

    async def test_cancellation_propagates(self):
        for name in TYPES:
            with self.subTest(provider=name), self.assertRaises(asyncio.CancelledError):
                await self.query(name, error=asyncio.CancelledError())


class ProviderCliTests(unittest.TestCase):
    def assert_discovery_limits(self, output):
        for service, details in (
            ("crt.sh HTTPS", ("per IP", "2023-06-09", " 5/minute,")),
            ("RapidDNS web search", ("per public IP", " 30/minute,")),
        ):
            line = next((line for line in output.splitlines() if service in line), "")
            self.assertTrue(line, f"Missing request limits for {service}")
            for detail in (*details, "hour unknown", "day unknown"):
                self.assertIn(detail, line)

    def test_help_shows_published_discovery_limits_offline(self):
        console = io.StringIO()
        with patch.object(sys, "argv", ["credentialthreat.py", "--help"]), redirect_stdout(console):
            with self.assertRaises(SystemExit) as end:
                CLI["parse_arguments"]()
        self.assertEqual(end.exception.code, 0)
        self.assert_discovery_limits(console.getvalue())

    def test_cli_queries_only_crtsh_and_rapiddns_and_reports_their_outcomes(self):
        for scenario in ("empty", "partial", "malformed", "filtered"):
            with self.subTest(scenario=scenario), ExitStack() as stack:
                main = CLI["main"]
                files = Mock()
                files.return_value.get_domains.return_value = [HOST]

                def request(url, **kwargs):
                    provider = urlsplit(url).hostname
                    if provider == "crt.sh":
                        return FixtureResponse(HITS["crt.sh"] if scenario == "partial" else EMPTY["crt.sh"])
                    if provider == "rapiddns.io":
                        if scenario == "partial":
                            raise dns_failure()
                        if scenario == "malformed":
                            return FixtureResponse("<html>Service unavailable</html>")
                        if scenario == "filtered":
                            return FixtureResponse(HITS["RapidDNS"].replace(CHILD, "other.example"))
                        return FixtureResponse(EMPTY["RapidDNS"])
                    raise AssertionError("unexpected request")

                fetch = stack.enter_context(patch.object(aiohttp.ClientSession, "get", side_effect=request))
                utils = CLI["utils"]
                for attr, value in (("get_workers", 1), ("configure_platform_settings", None)):
                    stack.enter_context(patch.object(utils, attr, return_value=value))
                hosts = []
                def links(args):
                    hosts.extend(args[0])
                    return [], set()
                stack.enter_context(patch.dict(main.__globals__, {
                    "ManageFiles": files, "time": Mock(perf_counter=time.perf_counter),
                    "parse_arguments": lambda: Mock(limit=5),
                    "create_pool": ThreadPool, "process_chunks_for_internallinks": links,
                    "process_chunks_for_networksearch": lambda _: ([], set(), [], {}),
                    "process_chunks_for_credentialsearch": lambda _: ([], {}),
                }))
                console = io.StringIO()
                stack.enter_context(redirect_stdout(console))
                stack.enter_context(redirect_stderr(console))
                with self.assertLogs(level="INFO") as logs:
                    code = main()
                output = " ".join(logs.output) + console.getvalue()
                requested_hosts = [urlsplit(call.args[0]).hostname for call in fetch.call_args_list]
                self.assertCountEqual(requested_hosts, ["crt.sh", "rapiddns.io"])
                self.assert_discovery_limits(output)
                self.assertNotIn("wayback", output.lower())
                self.assertNotIn("threatcrowd", output.lower())
                incomplete = scenario in ("partial", "malformed")
                self.assertEqual(code, int(incomplete))
                self.assertEqual("Report written with incomplete discovery" in output, incomplete)
                self.assertIn("crt.sh: hits=1" if scenario == "partial" else "crt.sh: hits=0 empty=1", output)
                if scenario == "malformed":
                    self.assertIn("RapidDNS: hits=0 empty=0 filtered=0 errors=1 (unexpected format=1)", output)
                elif scenario == "filtered":
                    self.assertIn("RapidDNS: hits=0 empty=0 filtered=1 errors=0", output)
                elif scenario == "partial":
                    self.assertIn("RapidDNS: hits=0 empty=0 filtered=0 errors=1 (DNS=1)", output)
                    self.assertIn(CHILD, hosts)
                else:
                    self.assertIn("RapidDNS: hits=0 empty=1", output)
                self.assertNotIn(HOST, output)
                self.assertNotIn(PRIVATE, output)
                files.write_csv_result_file.assert_called_once()
