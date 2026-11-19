import asyncio
import csv
import io
import os
import ssl
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import AsyncMock, Mock, patch

import aiohttp


ROOT = Path(__file__).resolve().parents[1]
MAIN = runpy.run_path(str(ROOT / "credentialthreat.py"))["main"]
DOMAIN = "docs.example.com"
QUOTAS = {"limits": {"search": {
    "minute": {"limit": 30, "remaining": 30},
    "hour": {"limit": 100, "remaining": 100},
    "day": {"limit": 500, "remaining": 494},
}}}
PDNS = {"responseCode": 200, "count": 21, "size": 1, "data": [
    {"query": DOMAIN + ".", "rrtype": "a", "answer": "PRIVATE-DATA"}
]}
SEARCH = {"total": 6, "has_more": False, "results": [
    {"page": {"domain": DOMAIN, "url": "PRIVATE-DATA"}}
]}


class Reply:
    def __init__(self, data, status=200, headers=None):
        self.data, self.status, self.headers = data, status, headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def json(self):
        return self.data


class CoverageTests(unittest.TestCase):
    def cli(self, mnemonic=PDNS, search=SEARCH, quotas=QUOTAS, args=None):
        calls = []
        def get(url, **kwargs):
            calls.append((url, kwargs))
            self.assertIs(kwargs.get("allow_redirects"), False)
            if url == "https://urlscan.io/user/quotas/":
                result = quotas
            elif url == "https://api.mnemonic.no/pdns/v3/" + DOMAIN:
                self.assertEqual(kwargs["params"], {"rrType": "a", "limit": 1})
                result = mnemonic
            elif url == "https://urlscan.io/api/v1/search/":
                self.assertIn('page.domain.keyword:"' + DOMAIN + '"', kwargs["params"]["q"])
                self.assertEqual(kwargs["params"]["size"], 1)
                result = search
            else:
                self.fail("unexpected destination")
            if isinstance(result, BaseException):
                raise result
            return result if isinstance(result, Reply) else Reply(result)

        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["credentialthreat.py", "coverage", *(args or [DOMAIN])]), \
             patch.object(aiohttp.ClientSession, "get", side_effect=get), \
             patch.dict(MAIN.__globals__, {"scan_subdomain_report": Mock(side_effect=AssertionError),
                                           "ManageFiles": Mock(side_effect=AssertionError)}), \
             redirect_stdout(out), redirect_stderr(err):
            status = MAIN()
        self.assertNotIn("PRIVATE-DATA", out.getvalue() + err.getvalue())
        return status, list(csv.DictReader(io.StringIO(out.getvalue()))), err.getvalue(), calls

    def test_cli_uses_exact_domains_returns_aggregate_counts_and_prints_quotas(self):
        code, rows, diagnostics, calls = self.cli(args=[DOMAIN.upper(), DOMAIN])
        self.assertEqual(code, 0)
        self.assertCountEqual([(r["domain"], r["source"], r["status"], r["count"]) for r in rows],
                              [(DOMAIN, "mnemonic", "hits", "21"), (DOMAIN, "urlscan.io", "hits", "6")])
        self.assertEqual(len(calls), 3)
        self.assertIn("10/min", diagnostics)
        self.assertIn("1000/day", diagnostics)
        self.assertIn("30/min", diagnostics)
        self.assertIn("100/hour", diagnostics)
        self.assertIn("500/day", diagnostics)

    def test_zero_and_lower_bound_are_explicit(self):
        code, rows, _, _ = self.cli(mnemonic={"responseCode":200,"count":0,"size":0,"data":[]},
                                    search=dict(SEARCH, total=10000, has_more=True))
        self.assertEqual(code, 0)
        self.assertCountEqual([(r["status"], r["count"], r["relation"]) for r in rows],
                              [("empty","0","exact"), ("hits","10000","at_least")])
        _, rows, _, _ = self.cli(search={"total":0,"results":[],"has_more":False})
        self.assertEqual(next(r for r in rows if r["source"] == "urlscan.io")["status"], "empty")

    def test_unexpected_http_timeout_and_schema_do_not_become_zero(self):
        for p, u, reasons in [
            (TimeoutError("PRIVATE-DATA"), Reply({},503), {"timeout","HTTP 503"}),
            (dict(PDNS, data=[]), dict(SEARCH, total=False), {"unexpected format"}),
            (dict(PDNS, responseCode=412), dict(SEARCH, results=[{"page":{"domain":"wrong.example"}}]),
             {"unexpected format"}),
            (dict(PDNS, count=-1), dict(SEARCH, results=[]), {"unexpected format"}),
            (dict(PDNS, size=True), dict(SEARCH, total=10001), {"unexpected format"}),
        ]:
            with self.subTest(reasons=reasons):
                code, rows, _, _ = self.cli(p, u)
                self.assertEqual(code, 1)
                self.assertEqual({r["reason"] for r in rows}, reasons)
                self.assertTrue(all(r["status"] == "errors" and not r["count"] for r in rows))

    def test_exhausted_hour_does_not_query_or_wait_for_next_window(self):
        limits = dict(QUOTAS["limits"]["search"], hour={"limit":100,"remaining":0})
        code, rows, _, calls = self.cli(quotas={"limits":{"search":limits}})
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 2)
        self.assertIn(("urlscan.io", "skipped", ""), [(r["source"],r["status"],r["count"]) for r in rows])

    def test_missing_quota_is_distinguished_from_failed_search(self):
        code, rows, _, calls = self.cli(quotas=Reply({}, 403))
        self.assertEqual((code, len(calls)), (1, 2))
        row = next(r for r in rows if r["source"] == "urlscan.io")
        self.assertEqual((row["status"],row["count"]), ("skipped",""))
        self.assertIn("403", row["reason"])

    def test_invalid_domain_never_reaches_a_provider(self):
        with self.assertRaises(SystemExit) as failure:
            self.cli(args=["https://other.example.com/"])
        self.assertEqual(failure.exception.code, 2)

    def test_a_single_source_run_does_not_repeat_the_other_service(self):
        code, rows, _, calls = self.cli(args=[DOMAIN, "--source", "urlscan.io"])
        self.assertEqual(code, 0)
        self.assertEqual([r["source"] for r in rows], ["urlscan.io"])
        self.assertEqual(len(calls), 2)  # quota plus one search

    def test_coverage_connector_verifies_tls_with_public_roots_and_respects_custom_ca(self):
        from credentialthreat.core import coverage
        from requests.certs import where
        real_connector = coverage.PublicDestinationConnector
        with patch.object(coverage, "PublicDestinationConnector", wraps=real_connector) as connector:
            self.assertEqual(self.cli()[0], 0)
            tls = connector.call_args.kwargs["ssl"]
            self.assertTrue(tls.check_hostname)
            self.assertEqual(tls.verify_mode, ssl.CERT_REQUIRED)
        with patch.dict(os.environ, {}, clear=False):
            for key in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
                os.environ.pop(key, None)
            for custom in (False, True):
                if custom:
                    os.environ["SSL_CERT_FILE"] = where()
                ctx = Mock()
                with self.subTest(custom=custom), patch("ssl.create_default_context", return_value=ctx):
                    self.assertIs(coverage.coverage_tls_context(), ctx)
                    if custom:
                        ctx.load_verify_locations.assert_not_called()
                    else:
                        ctx.load_verify_locations.assert_called_once_with(cafile=where())

    def test_a_disconnected_request_is_not_silently_repeated(self):
        from credentialthreat.core import coverage
        send = AsyncMock(side_effect=aiohttp.ServerDisconnectedError())
        with patch.object(aiohttp.TCPConnector, "connect", new=AsyncMock(return_value=Mock())), \
             patch.object(aiohttp.ClientRequest, "send", new=send), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = asyncio.run(coverage.run_coverage([DOMAIN], 1))
        self.assertEqual(code, 1)
        self.assertEqual(send.await_count, 2)  # one mnemonic query and one urlscan quota request

    def test_requested_samples_stop_at_the_utc_hour_boundary(self):
        now = datetime(2026, 11, 19, 12, 59, 59, tzinfo=timezone.utc)
        with patch("credentialthreat.core.coverage.utcnow", return_value=now), \
             patch("credentialthreat.core.coverage.asyncio.sleep", new_callable=AsyncMock) as sleep:
            code, rows, _, calls = self.cli(args=[DOMAIN, "--samples", "3"])
        self.assertEqual((code, len(rows), len(calls)), (1, 6, 3))
        self.assertEqual([r["sample"] for r in rows if r["status"] == "hits"], ["1", "1"])
        self.assertTrue(all(r["reason"] == "hour window ended" for r in rows if r["sample"] != "1"))
        sleep.assert_not_awaited()

    def test_minute_backoff_allows_the_next_sample_inside_the_same_hour(self):
        from credentialthreat.core import coverage
        now = datetime(2026, 11, 19, 12, 5, tzinfo=timezone.utc)
        queried = []
        async def sleep(seconds):
            nonlocal now
            now += timedelta(seconds=seconds)
        def get(url, **kwargs):
            queried.append(now)
            if len(queried) == 1:
                return Reply({"metaData":{"millisUntilResourcesAvailable":15000}}, 402)
            return Reply(PDNS)
        result = io.StringIO()
        with patch.object(coverage, "utcnow", side_effect=lambda: now), \
             patch.object(coverage.asyncio, "sleep", side_effect=sleep), redirect_stderr(io.StringIO()):
            ok = asyncio.run(coverage.collect(coverage.mnemonic, Mock(get=get), [DOMAIN], 2, now,
                             now + timedelta(minutes=55), csv.writer(result)))
        self.assertFalse(ok)
        self.assertEqual(len(queried), 2)
        self.assertGreaterEqual((queried[1] - queried[0]).total_seconds(), 15)
        self.assertIn("hits,21,exact", result.getvalue())

    def test_hourly_budget_is_shared_round_robin_across_three_domains(self):
        from credentialthreat.core import coverage
        now = datetime(2026, 11, 19, 12, 5, tzinfo=timezone.utc)
        domains = ["one.example.com", "two.example.com", "three.example.com"]
        requested = []
        async def sleep(seconds):
            nonlocal now
            now += timedelta(seconds=seconds)
        def get(url, **kwargs):
            if url == coverage.urlscan.QUOTA_URL:
                return Reply(QUOTAS)
            requested.append(kwargs["params"]["q"].split('"')[1])
            return Reply({"total":0, "has_more":False, "results":[]})
        output = io.StringIO()
        with patch.object(coverage, "utcnow", side_effect=lambda: now), \
             patch.object(coverage.asyncio, "sleep", side_effect=sleep), redirect_stderr(io.StringIO()):
            ok = asyncio.run(coverage.collect(coverage.urlscan, Mock(get=get), domains, 50, now,
                             now + timedelta(minutes=55), csv.writer(output)))
        self.assertFalse(ok)
        self.assertEqual(requested, domains * 33 + domains[:1])
        rows = list(csv.reader(io.StringIO(output.getvalue())))
        self.assertEqual(sum(r[4] == "skipped" for r in rows), 50)
        self.assertEqual(len(rows), 150)

    def test_minute_remaining_applies_at_the_time_the_quota_is_received(self):
        from credentialthreat.core import coverage
        start = datetime(2026, 11, 19, 12, 0, 59, tzinfo=timezone.utc)
        now = start
        issued = []
        async def sleep(seconds):
            nonlocal now
            now += timedelta(seconds=seconds)
        def get(url, **kwargs):
            nonlocal now
            if url == coverage.urlscan.QUOTA_URL:
                now = start + timedelta(seconds=2)
                return Reply({"limits":{"search":dict(QUOTAS["limits"]["search"],
                                                      minute={"limit":30,"remaining":0})}})
            issued.append(now)
            return Reply(SEARCH)
        with patch.object(coverage, "utcnow", side_effect=lambda: now), \
             patch.object(coverage.asyncio, "sleep", side_effect=sleep), redirect_stderr(io.StringIO()):
            asyncio.run(coverage.collect(coverage.urlscan, Mock(get=get), [DOMAIN], 1, start,
                        start.replace(hour=13, minute=0, second=0), csv.writer(io.StringIO())))
        self.assertEqual(issued, [start.replace(minute=2, second=0)])
