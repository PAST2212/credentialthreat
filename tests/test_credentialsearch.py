import asyncio
import re
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

import aiohttp

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


def case_insensitive_findings(scanner, data):
    """The matcher's previous implementation: the assignment rule run with IGNORECASE on the raw text."""
    labels_by_span = {}
    for match in re.finditer(scanner.credential_pattern, data, flags=re.IGNORECASE | re.MULTILINE):
        labels_by_span[match.span("value")] = [match["label"].lower()]
    for pattern_name, pattern in scanner.additional_patterns.items():
        for match in re.finditer(pattern, data):
            labels = labels_by_span.setdefault(match.span(), [])
            if pattern_name not in labels:
                labels.append(pattern_name)
    return [(" + ".join(labels), "[REDACTED]") for labels in labels_by_span.values()]


def minified_script(size):
    """Deterministic JavaScript-like text without credentials, as large bundles look to the matcher."""
    parts, index = [], 0
    while sum(map(len, parts)) < size:
        parts.append(f'function f{index}(e,t){{return e.data{index}?t.render("Item{index}",{{id:e.id,label:"Label {index}"}}):null}};')
        index += 1
    return "".join(parts)


class MatcherTests(unittest.TestCase):
    def test_field_names_match_in_any_case_like_before(self):
        scanner = ScanerCredentials()
        samples = [
            'API_KEY = "FIXTUREONLYVALUE1"', 'Client_Secret: \'FIXTUREONLYVALUE2\'', 'apisecret => "FIXTUREONLYVALUE3"',
            'AWSSECRETKEY="FIXTUREONLYVALUE4" and awssecretkey="FIXTUREONLYVALUE5"',
            # Non-ASCII letters that Unicode case-insensitive matching folds onto ASCII ones.
            'acce\u017fs_key = "FIXTUREONLYVALUE6"', 'ap\u0130_key = "FIXTUREONLYVALUE7"', 'ap\u0131_key = "FIXTUREONLYVALUE8"',
            'api_\u212aey = "FIXTUREONLYVALUE9"', 'api_key = "FIXTURE\u212aONLY\u017fVALUE"',
            '\u00dcbersicht api_key = "FIXTUREONLYVALUE10" ' + "x" * 50 + ' AKIA' + 'TEST' * 4,
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(scanner._findings(sample), case_insensitive_findings(scanner, sample))
                self.assertTrue(scanner._findings(sample))

    def test_fetch_credentials_mode_is_not_a_candidate(self):
        # The Fetch API option credentials: "same-origin" was every match on one production site.
        scanner = ScanerCredentials()
        for sample in ('fetch(u,{mode:"cors",credentials:"same-origin"})', "credentials: 'same-origin'",
                       'o.credentials="omit":o.credentials="same-origin"', 'CREDENTIALS = "SAME-ORIGIN"'):
            with self.subTest(sample=sample):
                self.assertEqual(scanner._findings(sample), [])
                self.assertEqual(case_insensitive_findings(scanner, sample), [])
        self.assertEqual(scanner._findings('credentials = "same-origin-FIXTUREONLY"'), [("credentials", "[REDACTED]")])

    def test_assignment_does_not_run_into_the_next_property(self):
        # On one production site, `withCredentials:this.withCredentials,requestType:"…"` was a credentials candidate:
        # the separator after the field name ran across the comma into the next property's value.
        scanner = ScanerCredentials()
        for sample in ('x={withCredentials:this.withCredentials,requestType:"arraybuffer"}',
                       'e.withCredentials=t.withCredentials,e.responseType="arraybuffer"',
                       'init = { credentials: options.credentials, mode: "navigate-fixture" }'):
            with self.subTest(sample=sample):
                self.assertEqual(scanner._findings(sample), [])
                self.assertEqual(case_insensitive_findings(scanner, sample), [])
        for sample, label in (('config={credentials:"FIXTUREONLYVALUE"}', "credentials"),
                              ('awsCredentials = "FIXTUREONLYVALUE"', "credentials"),
                              ('api_key_prod = "FIXTUREONLYVALUE"', "api_key"),
                              ('client_secret.value = "FIXTUREONLYVALUE"', "client_secret")):
            with self.subTest(sample=sample):
                self.assertEqual(scanner._findings(sample), [(label, "[REDACTED]")])

    def test_assignment_rule_does_not_scan_text_case_insensitively(self):
        # Case-insensitive matching of the field-name alternation costs about 1.5 s per MB of script
        # and blocks the worker's event loop meanwhile. Compare on this machine, not against a fixed time.
        # The runs alternate and the fastest of each counts, so a busy machine slows both sides alike.
        # The new matcher is about 7x faster; the test asks for 2x.
        scanner = ScanerCredentials()
        text = minified_script(120_000)

        def timed(run):
            start = time.perf_counter()
            run()
            return time.perf_counter() - start

        previous, current = [], []
        for _ in range(5):
            previous.append(timed(lambda: case_insensitive_findings(scanner, text)))
            current.append(timed(lambda: scanner._findings(text)))
        self.assertLess(min(current), min(previous) / 2,
                        f"_findings took {min(current):.3f}s, case-insensitive {min(previous):.3f}s")


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


class ModuleImportCollectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_scripts_report_the_in_scope_modules_they_import(self):
        script = ('import{a}from"./dep.js";import"https://cdn.other.test/x.js";'
                  'import("/lazy.js");import"./pic.png";')
        scanner = ScanerCredentials(scope=["example.com"])
        session = session_returning(response(200, script, {"Content-Type": "application/javascript"}))
        await scanner._get_request((SITE, SITE + "/js/app.js"), {}, session)
        self.assertEqual(scanner.imports, {(SITE, SITE + "/js/dep.js"), (SITE, SITE + "/lazy.js")})

    async def test_only_scripts_that_loaded_are_searched_for_imports(self):
        for status, content_type in ((200, "text/css"), (200, "text/html"), (404, "application/javascript")):
            with self.subTest(status=status, content_type=content_type):
                scanner = ScanerCredentials(scope=["example.com"])
                session = session_returning(response(status, 'import"./dep.js";', {"Content-Type": content_type}))
                await scanner._get_request((SITE, SITE + "/style"), {}, session)
                self.assertEqual(scanner.imports, set())


class ConnectTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_page_and_resource_stages_retry_a_connect_timeout_once(self):
        # Hosts in these stages have already answered; a connect timeout there is mostly a blocked loop.
        # The link stage probes discovered hosts, where a connect timeout usually means a dead host.
        scanners = (
            (ScanerCredentials(scope=["example.com"]), lambda url: (SITE, url), 2),
            (ScanerNetworkResources(scope=["example.com"]), lambda url: url, 2),
            (ScanerInternalLinks(scope=["example.com"]), lambda url: url, 1),
        )
        for scanner, argument, requests in scanners:
            with self.subTest(scanner=type(scanner).__name__):
                session = session_returning(aiohttp.ConnectionTimeoutError(), response(200, "ok"))
                await scanner._get_request(argument(SITE + "/a.js"), {}, session)
                self.assertEqual(session.get.call_count, requests)


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
