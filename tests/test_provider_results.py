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

from credentialthreat.core.discovery import QueryResult, log_query_summary
from credentialthreat.core.subdomainsearch import SUBDOMAIN_SERVICES, SubdomainScanner
from credentialthreat.recon.anubisdb import ScanerAnubisDb
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
    "AnubisDB": "[]",
}
HITS = {
    "crt.sh": json.dumps([{"name_value": "*." + CHILD}]),
    "RapidDNS": TABLE_HEAD + "<tbody><tr><th>1</th><td>" + CHILD + "</td><td>192.0.2.1</td><td>A</td><td>2025</td></tr>" + TABLE_END,
    "AnubisDB": json.dumps([CHILD]),
}
TYPES = {
    "crt.sh": ScanerCrtsh,
    "RapidDNS": ScanerRapidDns,
    "AnubisDB": ScanerAnubisDb,
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
        # AnubisDB publishes 60 requests per 10 seconds.
        for name, minimum_pause in (("crt.sh", 12), ("RapidDNS", 2), ("AnubisDB", 1)):
            with self.subTest(provider=name):
                session = Mock()
                session.get.side_effect = [FixtureResponse(PRIVATE, 502), FixtureResponse(HITS[name])]
                with patch("asyncio.sleep", new=AsyncMock()) as pause:
                    result, = await TYPES[name]().get_report([HOST], session)
                self.assertEqual((result.state, result.values), ("hits", {CHILD}))
                self.assertEqual(session.get.call_count, 2)
                self.assertGreaterEqual(pause.await_args.args[0], minimum_pause)

    async def test_queries_for_several_domains_keep_to_each_providers_published_rate(self):
        # A scan of seven domains sent crt.sh seven queries within 43 s; crt.sh publishes 5 per minute.
        for name, per_minute in (("crt.sh", 5), ("RapidDNS", 30), ("AnubisDB", 360)):
            with self.subTest(provider=name):
                session = Mock()
                session.get.side_effect = [FixtureResponse(EMPTY[name]) for _ in range(3)]
                with patch("asyncio.sleep", new=AsyncMock()) as pause:
                    results = await TYPES[name]().get_report(["a.example", "b.example", "c.example"], session)
                self.assertEqual([result.state for result in results], ["empty"] * 3)
                self.assertEqual(pause.await_count, 2)
                for call in pause.await_args_list:
                    self.assertGreaterEqual(call.args[0], 60 / per_minute)

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

    async def test_crtsh_query_waits_until_crtsh_itself_gives_up(self):
        # crt.sh answered a domain with 1,500 hosts after 14 to 64 s and ends a query itself with HTTP 504
        # after 120 s. The discovery session allows 30 s, which cut off the large domains.
        session = Mock()
        session.get.return_value = FixtureResponse(EMPTY["crt.sh"])
        result, = await ScanerCrtsh().get_report([HOST], session)
        self.assertEqual(result.state, "empty")
        timeout = session.get.call_args.kwargs.get("timeout")
        self.assertIsInstance(timeout, aiohttp.ClientTimeout)
        self.assertGreater(timeout.total, 120)
        # An unreachable crt.sh still fails fast.
        self.assertIsNotNone(timeout.connect)
        self.assertLessEqual(timeout.connect, 30)

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
            "AnubisDB": ['{"error":"Invalid domain"}', "[1]", json.dumps([CHILD, None])],
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
        with patch("asyncio.sleep", new=AsyncMock()):  # the pause between domains
            results = await scanner.get_report(["unavailable.example", "empty.example", HOST], session)
        self.assertEqual([q.state for q in results], ["error", "empty", "hits"])
        async with SubdomainScanner() as coordinator:
            async def provider_batch(scanner, domains, service):
                if service == "crtsh":
                    return results
                raise RuntimeError(PRIVATE)
            with patch.object(coordinator, "scan_with_rate_limit", new=provider_batch):
                combined = await coordinator.tasks_subdomains(["unavailable.example", "empty.example", HOST])
        # One result per provider and domain; each failing provider batch marks its three domains as errors.
        self.assertEqual(len(combined), 3 * len(SUBDOMAIN_SERVICES))
        self.assertEqual([q.values for q in combined if q.state == "hits"], [{CHILD}])
        self.assertEqual(sum(q.state == "error" for q in combined), 1 + 3 * (len(SUBDOMAIN_SERVICES) - 1))

    async def test_rapiddns_reports_how_many_records_it_holds(self):
        # Without an account RapidDNS shows 100 rows and states the full total above the table.
        total = '<div style="margin: 0 8px;">Total: <span style="color: #39cfca; ">5</span></div>'
        partial = await self.query("RapidDNS", total + HITS["RapidDNS"])
        self.assertEqual((partial.state, partial.records, partial.available), ("hits", 1, 5))
        complete = await self.query("RapidDNS", total.replace(">5<", ">1<") + HITS["RapidDNS"])
        self.assertEqual((complete.records, complete.available), (1, 1))
        unstated = await self.query("RapidDNS", HITS["RapidDNS"])
        self.assertIsNone(unstated.available)

    async def test_rapiddns_total_is_read_only_beside_its_label(self):
        # Without a count beside the label, a later number on the page must not be taken for the total.
        body = "<div>Total: <b>5</b></div>" + HITS["RapidDNS"] + "<footer><span>2025</span></footer>"
        result = await self.query("RapidDNS", body)
        self.assertIsNone(result.available)

    def test_partial_results_are_a_warning_but_not_a_failed_query(self):
        results = [QueryResult("RapidDNS", HOST, 100, frozenset([CHILD]), available=10891),
                   QueryResult("RapidDNS", "other.example", 3, frozenset(["a.other.example"]), available=3)]
        with self.assertLogs(level="INFO") as logs:
            self.assertFalse(log_query_summary(results))
        self.assertEqual([(record.getMessage(), record.levelname) for record in logs.records], [
            ("RapidDNS: hits=2 empty=0 filtered=0 errors=0, partial=1 (100 of 10891 records)", "WARNING")])
        self.assertNotIn(HOST, " ".join(logs.output))

    async def test_cancellation_propagates(self):
        for name in TYPES:
            with self.subTest(provider=name), self.assertRaises(asyncio.CancelledError):
                await self.query(name, error=asyncio.CancelledError())


def otx_page(urls, has_next, full_size):
    return json.dumps({"url_list": [{"url": url, "domain": HOST} for url in urls], "has_next": has_next,
                       "full_size": full_size, "page_num": 1, "limit": 500})


class OtxUrlTests(unittest.IsolatedAsyncioTestCase):
    # AlienVault OTX lists URLs seen under a domain. On a large retailer, 146 of 200 URLs that the crawl had never
    # requested were readable pages: pages that no start page links to.
    async def report(self, *replies):
        from credentialthreat.recon.otx import ScanerOtxUrls
        session = Mock()
        session.get.side_effect = list(replies)
        with patch("asyncio.sleep", new=AsyncMock()) as pause:
            result, = await ScanerOtxUrls().get_report([HOST], session)
        return result, session, pause

    async def test_page_urls_in_scope_are_reported_as_urls(self):
        result, session, _ = await self.report(FixtureResponse(otx_page([
            f"https://{CHILD}/docs/start#top", f"http://{HOST}/a?b=1", "https://other.example/x",
            f"https://{CHILD}/logo.png", f"https://user:pw@{CHILD}/private", "not a url"], False, 6)))
        self.assertEqual((result.provider, result.kind, result.state, result.records), ("AlienVault OTX", "urls", "hits", 6))
        self.assertEqual(result.values, {f"https://{CHILD}/docs/start", f"http://{HOST}/a?b=1"})
        url, = session.get.call_args.args
        self.assertEqual((urlsplit(url).hostname, urlsplit(url).path),
                         ("otx.alienvault.com", f"/api/v1/indicators/domain/{HOST}/url_list"))
        self.assertEqual(session.get.call_args.kwargs["params"], {"limit": 500, "page": 1})

    async def test_pages_are_read_up_to_the_cap_with_a_pause_between_them(self):
        from credentialthreat.recon.otx import ScanerOtxUrls
        cap = ScanerOtxUrls.max_pages
        pages = [FixtureResponse(otx_page([f"https://{CHILD}/p{page}/{i}" for i in range(2)], True, 900))
                 for page in range(cap + 3)]
        result, session, pause = await self.report(*pages)
        self.assertEqual([call.kwargs["params"]["page"] for call in session.get.call_args_list], list(range(1, cap + 1)))
        self.assertEqual((len(result.values), result.records, result.available, result.partial), (2 * cap, 2 * cap, 900, True))
        self.assertEqual(pause.await_count, cap - 1)
        self.assertGreaterEqual(pause.await_args.args[0], 1)

    async def test_a_failing_later_page_keeps_the_urls_already_read(self):
        # A later page answered HTTP 504 after 60 s; the earlier pages are still valid.
        for failure in (FixtureResponse(PRIVATE, 504), asyncio.TimeoutError(PRIVATE), dns_failure()):
            with self.subTest(failure=type(failure).__name__):
                result, _, _ = await self.report(FixtureResponse(otx_page([f"https://{CHILD}/a"], True, 900)), failure)
                self.assertEqual((result.state, result.reason, result.values), ("hits", None, {f"https://{CHILD}/a"}))
                self.assertEqual((result.records, result.available, result.partial), (1, 900, True))

    async def test_empty_failed_and_malformed_first_pages(self):
        empty, _, _ = await self.report(FixtureResponse(otx_page([], False, 0)))
        self.assertEqual((empty.state, empty.records, empty.reason), ("empty", 0, None))
        dns, _, _ = await self.report(dns_failure())
        self.assertEqual((dns.state, dns.reason), ("error", "DNS"))
        retried, session, _ = await self.report(FixtureResponse(PRIVATE, 504), FixtureResponse(PRIVATE, 504))
        self.assertEqual((retried.reason, session.get.call_count), ("HTTP 504", 2))
        for body in ('{"url_list": "x", "has_next": false}', "<html>sign in</html>",
                     json.dumps({"url_list": [{"url": 5}], "has_next": False, "full_size": 1}),
                     json.dumps({"url_list": [], "has_next": "no", "full_size": 0})):
            with self.subTest(body=body):
                malformed, _, _ = await self.report(FixtureResponse(body))
                self.assertEqual((malformed.state, malformed.reason, malformed.values), ("error", "unexpected format", frozenset()))

    async def test_host_providers_report_hosts(self):
        for name in TYPES:
            with self.subTest(provider=name):
                session = Mock()
                session.get.return_value = FixtureResponse(HITS[name])
                result, = await TYPES[name]().get_report([HOST], session)
                self.assertEqual(result.kind, "hosts")


class ProviderCliTests(unittest.TestCase):
    def assert_discovery_limits(self, output):
        for service, details in (
            ("crt.sh HTTPS", ("per IP", "2023-06-09", " 5/minute,")),
            ("RapidDNS web search", ("per public IP", " 30/minute,")),
            ("AnubisDB API", ("per source IP", " 360/minute (60 per 10 seconds),")),
            ("AlienVault OTX URL list", ("without API key", "minute unknown,", "at most 4 requests per domain")),
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

    def test_cli_queries_only_its_discovery_providers_and_reports_their_outcomes(self):
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
                    if provider == "anubisdb.com":
                        if scenario == "malformed":
                            return FixtureResponse('{"error":"Invalid domain"}')
                        return FixtureResponse('["' + CHILD + '"]' if scenario == "partial" else "[]")
                    if provider == "otx.alienvault.com":
                        if scenario == "malformed":
                            return FixtureResponse("<html>Service unavailable</html>")
                        return FixtureResponse(otx_page([f"https://{CHILD}/deep"] if scenario == "partial" else [], False,
                                                        1 if scenario == "partial" else 0))
                    raise AssertionError("unexpected request")

                fetch = stack.enter_context(patch.object(aiohttp.ClientSession, "get", side_effect=request))
                # AnubisDB accepts submissions; the scanner must never send it the names it discovered.
                submit = stack.enter_context(patch.object(aiohttp.ClientSession, "post", side_effect=AssertionError))
                utils = CLI["utils"]
                for attr, value in (("get_workers", 1), ("configure_platform_settings", None)):
                    stack.enter_context(patch.object(utils, attr, return_value=value))
                hosts = []
                def links(args):
                    hosts.extend(args[0])
                    return [], [], set(), [], {}
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
                self.assertCountEqual(requested_hosts, ["crt.sh", "rapiddns.io", "anubisdb.com", "otx.alienvault.com"])
                submit.assert_not_called()
                self.assert_discovery_limits(output)
                self.assertNotIn("wayback", output.lower())
                self.assertNotIn("threatcrowd", output.lower())
                incomplete = scenario in ("partial", "malformed")
                self.assertEqual(code, int(incomplete))
                self.assertEqual("Report written with incomplete discovery" in output, incomplete)
                self.assertIn("crt.sh: hits=1" if scenario == "partial" else "crt.sh: hits=0 empty=1", output)
                if scenario == "malformed":
                    self.assertIn("AlienVault OTX: hits=0 empty=0 filtered=0 errors=1 (unexpected format=1)", output)
                else:
                    self.assertIn("AlienVault OTX: hits=1" if scenario == "partial" else "AlienVault OTX: hits=0 empty=1", output)
                if scenario == "malformed":
                    self.assertIn("AnubisDB: hits=0 empty=0 filtered=0 errors=1 (unexpected format=1)", output)
                else:
                    self.assertIn("AnubisDB: hits=1" if scenario == "partial" else "AnubisDB: hits=0 empty=1", output)
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
