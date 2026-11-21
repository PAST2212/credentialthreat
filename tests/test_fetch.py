import asyncio
from collections import Counter
import socket
import ssl
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import aiohttp
from aiohttp import web

from credentialthreat.core.fetch import HostPacer, fetch_text
from credentialthreat.core.website import DestinationBlocked
from http_doubles import FakeClock, response, session_returning


SCOPE = ["example.com"]
PAGE = "https://www.example.com/"


class HostPacerTests(unittest.IsolatedAsyncioTestCase):
    async def test_throttling_pauses_every_request_to_that_host_only(self):
        clock = FakeClock()
        pacer = HostPacer(rate=10, clock=clock.now, sleep=clock.sleep)
        await pacer.wait("a.example.com")
        pacer.throttled("a.example.com", 2.0)
        await pacer.wait("b.example.com")
        self.assertEqual(clock.slept, [])
        await pacer.wait("a.example.com")
        self.assertEqual(clock.slept, [2.0])

    async def test_rate_halves_when_throttled_and_never_recovers_beyond_the_start(self):
        clock = FakeClock()
        pacer = HostPacer(rate=8, clock=clock.now, sleep=clock.sleep)
        pacer.throttled("a.example.com", 0)
        pacer.throttled("a.example.com", 0)
        await pacer.wait("a.example.com")
        await pacer.wait("a.example.com")
        self.assertEqual(clock.slept, [0.5])  # 2 requests per second after two halvings
        for _ in range(1000):
            pacer.succeeded("a.example.com")
        clock.slept.clear()
        await pacer.wait("a.example.com")
        await pacer.wait("a.example.com")
        self.assertEqual(clock.slept, [0.5, 0.125])  # back at 8 per second, not faster

    async def test_requests_beyond_the_host_share_wait_outside_the_http_client(self):
        # aiohttp counts time spent waiting for a pooled connection against the request timeout.
        pacer = HostPacer(rate=1000, connections=1)
        release = asyncio.Event()
        sent = []

        def get(url, **kwargs):
            sent.append(url.rsplit("/", 1)[1])

            async def enter(*args):
                if url.endswith("/slow"):
                    await release.wait()
                return response(200, "ok")
            manager = MagicMock()
            manager.__aenter__.side_effect = enter
            return manager

        session = Mock(get=get)
        first = asyncio.create_task(fetch_text(session, PAGE + "slow", {}, scope=SCOPE, pacer=pacer))
        second = asyncio.create_task(fetch_text(session, PAGE + "next", {}, scope=SCOPE, pacer=pacer))
        await asyncio.sleep(0.05)
        self.assertEqual(sent, ["slow"])
        release.set()
        await asyncio.gather(first, second)
        self.assertEqual(sent, ["slow", "next"])

    async def test_throttled_fetch_pauses_the_host_before_retrying(self):
        clock = FakeClock()
        pacer = HostPacer(rate=1000, clock=clock.now, sleep=clock.sleep)
        sent_at = []
        replies = iter([response(429, "", {"Retry-After": "3"}), response(200, "ok")])

        def get(url, **kwargs):
            sent_at.append(clock.now())
            manager = MagicMock()
            manager.__aenter__.return_value = next(replies)
            return manager

        page = await fetch_text(Mock(get=get), PAGE, {}, scope=SCOPE, pacer=pacer, sleep=clock.sleep)
        self.assertEqual(page.text, "ok")
        self.assertGreaterEqual(sent_at[1] - sent_at[0], 3.0)


class FetchTests(unittest.IsolatedAsyncioTestCase):
    async def fetch(self, session, url=PAGE, scope=SCOPE, **kwargs):
        self.sleep = AsyncMock()
        self.outcomes = Counter()
        return await fetch_text(session, url, {}, scope=scope, outcomes=self.outcomes, sleep=self.sleep, **kwargs)

    def requested(self, session):
        return [call.args[0] for call in session.get.call_args_list]

    async def test_throttled_request_is_retried_after_the_announced_delay(self):
        session = session_returning(response(429, "slow down", {"Retry-After": "2"}), response(200, "<html>ok</html>"))
        page = await self.fetch(session)
        self.assertEqual((page.url, page.text), (PAGE, "<html>ok</html>"))
        self.sleep.assert_awaited_once_with(2.0)
        self.assertEqual(self.outcomes, Counter({"ok": 1}))

    async def test_persistent_throttling_is_counted_and_never_parsed(self):
        replies = [response(429, "slow down") for _ in range(3)]
        session = session_returning(*replies)
        self.assertIsNone(await self.fetch(session))
        self.assertEqual(session.get.call_count, 3)
        self.assertEqual(self.outcomes, Counter({"HTTP 429": 1}))
        self.assertEqual([reply.content.reads for reply in replies], [0, 0, 0])

    async def test_unavailable_service_is_retried_and_long_delays_are_capped(self):
        session = session_returning(response(503, "", {"Retry-After": "3600"}), response(200, "ok"))
        page = await self.fetch(session)
        self.assertEqual(page.text, "ok")
        self.sleep.assert_awaited_once_with(30.0)

    async def test_read_timeout_is_retried(self):
        session = session_returning(asyncio.TimeoutError(), response(200, "ok"))
        self.assertEqual((await self.fetch(session)).text, "ok")
        self.assertEqual(session.get.call_count, 2)

    async def test_connect_timeout_is_retried_when_the_caller_allows_it(self):
        session = session_returning(aiohttp.ConnectionTimeoutError(), response(200, "ok"))
        page = await self.fetch(session, connect_retries=1)
        self.assertEqual(page.text, "ok")
        self.assertEqual(session.get.call_count, 2)
        self.assertEqual(self.outcomes, Counter({"ok": 1}))

    async def test_connect_timeout_retry_leaves_the_other_attempts_intact(self):
        session = session_returning(aiohttp.ConnectionTimeoutError(), asyncio.TimeoutError(), asyncio.TimeoutError(),
                                    response(200, "ok"))
        page = await self.fetch(session, connect_retries=1)
        self.assertEqual(page.text, "ok")
        self.assertEqual(session.get.call_count, 4)
        self.assertEqual(self.outcomes, Counter({"ok": 1}))

    async def test_connect_timeout_retries_are_bounded(self):
        session = session_returning(aiohttp.ConnectionTimeoutError(), aiohttp.ConnectionTimeoutError())
        self.assertIsNone(await self.fetch(session, connect_retries=1))
        self.assertEqual(session.get.call_count, 2)
        self.assertEqual(self.outcomes, Counter({"connect timeout": 1}))

    async def test_connection_failures_are_counted_by_cause(self):
        key = Mock()
        failures = (
            (aiohttp.ClientConnectorDNSError(key, socket.gaierror(11001, "getaddrinfo failed")), "DNS"),
            (aiohttp.ClientConnectorDNSError(key, DestinationBlocked("private")), "destination blocked"),
            (aiohttp.ClientConnectorCertificateError(key, ssl.SSLCertVerificationError("self-signed")), "TLS"),
            (aiohttp.ClientConnectorSSLError(key, ssl.SSLError("handshake")), "TLS"),
            (aiohttp.ClientConnectorError(key, ConnectionRefusedError("refused")), "connection"),
        )
        for error, cause in failures:
            with self.subTest(error=type(error).__name__, cause=cause):
                session = session_returning(error)
                self.assertIsNone(await self.fetch(session))
                self.assertEqual(session.get.call_count, 1)
                self.assertEqual(self.outcomes, Counter({cause: 1}))

    async def test_unreachable_host_is_not_retried(self):
        for error in (aiohttp.ConnectionTimeoutError(), aiohttp.ClientConnectorError(Mock(), OSError("refused"))):
            with self.subTest(error=type(error).__name__):
                session = session_returning(error)
                self.assertIsNone(await self.fetch(session))
                self.assertEqual(session.get.call_count, 1)
                self.assertEqual(sum(self.outcomes.values()), 1)
                self.assertNotIn("ok", self.outcomes)

    async def test_in_scope_redirects_are_followed_to_the_final_page(self):
        session = session_returning(
            response(302, "", {"Location": "https://www.example.com/"}),
            response(301, "", {"Location": "/de/"}),
            response(200, "<html>de</html>"),
        )
        page = await self.fetch(session, url="https://example.com/")
        self.assertEqual((page.url, page.text), ("https://www.example.com/de/", "<html>de</html>"))
        self.assertEqual(self.requested(session),
                         ["https://example.com/", "https://www.example.com/", "https://www.example.com/de/"])
        self.assertTrue(all(call.kwargs["allow_redirects"] is False for call in session.get.call_args_list))

    async def test_out_of_scope_redirect_is_never_requested(self):
        for location in ("https://example.com.evil.invalid/", "https://other.invalid/x", "mailto:a@example.com"):
            with self.subTest(location=location):
                redirect = response(302, "unused", {"Location": location})
                session = session_returning(redirect)
                self.assertIsNone(await self.fetch(session))
                self.assertEqual(self.requested(session), [PAGE])
                self.assertEqual(redirect.content.reads, 0)
                self.assertEqual(self.outcomes, Counter({"redirect skipped": 1}))

    async def test_without_a_scope_no_redirect_is_followed(self):
        session = session_returning(response(301, "", {"Location": "/de/"}))
        self.assertIsNone(await self.fetch(session, scope=()))
        self.assertEqual(session.get.call_count, 1)

    async def test_redirect_chain_is_bounded(self):
        session = session_returning(*[response(302, "", {"Location": f"/hop/{i}"}) for i in range(10)])
        self.assertIsNone(await self.fetch(session))
        self.assertEqual(session.get.call_count, 4)
        self.assertEqual(self.outcomes, Counter({"too many redirects": 1}))

    async def test_binary_content_type_is_not_downloaded(self):
        for content_type in ("image/png", "application/pdf", "video/mp4", "font/woff2", "application/octet-stream"):
            with self.subTest(content_type=content_type):
                binary = response(200, b"\x89PNG" * 1000, {"Content-Type": content_type})
                self.assertIsNone(await self.fetch(session_returning(binary)))
                self.assertEqual(binary.content.reads, 0)
                self.assertEqual(self.outcomes, Counter({"binary": 1}))

    async def test_text_content_types_are_read(self):
        for content_type in ("text/html; charset=utf-8", "application/javascript", "application/json", "image/svg+xml", ""):
            with self.subTest(content_type=content_type):
                page = await self.fetch(session_returning(response(200, "var a = 1;", {"Content-Type": content_type})))
                self.assertEqual(page.text, "var a = 1;")

    async def test_body_is_cut_at_the_size_limit(self):
        body = "a" * 5000
        page = await self.fetch(session_returning(response(200, body)), max_bytes=1000)
        self.assertEqual(len(page.text), 1000)
        self.assertEqual(self.outcomes, Counter({"truncated": 1}))

    async def test_error_status_bodies_are_still_returned_for_scanning(self):
        page = await self.fetch(session_returning(response(500, "debug trace")))
        self.assertEqual((page.status, page.text), (500, "debug trace"))

    async def test_a_response_that_is_not_http_is_counted_apart_from_errors(self):
        # Push and VPN endpoints answer on port 443 with binary data; aiohttp raises ClientResponseError("Expected
        # HTTP/"). Counted and logged as "error", these hid the requests that the scanner itself got wrong.
        parse_error = aiohttp.ClientResponseError(Mock(), (), status=400, message="Expected HTTP/: PRIVATEFIXTUREONLY")
        with self.assertNoLogs("credentialthreat.core.fetch", level="ERROR"):
            self.assertIsNone(await self.fetch(session_returning(parse_error)))
        self.assertEqual(self.outcomes, Counter({"invalid response": 1}))

    async def test_error_status_bodies_are_counted_apart_from_ok(self):
        for status in (400, 403, 404, 500):
            with self.subTest(status=status):
                await self.fetch(session_returning(response(status, "error page")))
                self.assertEqual(self.outcomes, Counter({f"HTTP {status} read": 1}))

    async def test_bot_challenge_is_neither_read_nor_retried(self):
        challenges = (
            (400, {"x-kpsdk-ct": "token"}),         # Kasada
            (429, {"x-kpsdk-ct": "token"}),
            (403, {"cf-mitigated": "challenge"}),   # Cloudflare
            (503, {"cf-mitigated": "challenge"}),
        )
        for status, headers in challenges:
            with self.subTest(status=status, headers=headers):
                challenge = response(status, '<script src="/ips.js?KP_UIDz=1"></script>', headers)
                session = session_returning(challenge)
                self.assertIsNone(await self.fetch(session))
                self.assertEqual(session.get.call_count, 1)
                self.assertEqual(challenge.content.reads, 0)
                self.sleep.assert_not_awaited()
                self.assertEqual(self.outcomes, Counter({"bot challenge": 1}))

    async def test_anubis_challenge_answered_with_200_is_a_bot_challenge(self):
        # Anubis (Techaro) answers with HTTP 200 and a proof-of-work page without site content. It sets a cookie
        # to test cookie support; the prefix is "techaro.lol" by default and site-specific otherwise.
        for cookies in (
            [("Set-Cookie", "techaro.lol-anubis-auth=; Path=/"),
             ("Set-Cookie", "techaro.lol-anubis-cookie-verification=0199a; Path=/")],
            [("Set-Cookie", "uni-web-anubis-cookie-verification=0199a; Path=/; Domain=example.org; Secure")],
        ):
            with self.subTest(cookies=cookies):
                challenge = response(200, '<script src="/.within.website/x/cmd/anubis/static/js/main.mjs"></script>',
                                     [("Content-Type", "text/html; charset=utf-8"), *cookies])
                session = session_returning(challenge)
                self.assertIsNone(await self.fetch(session))
                self.assertEqual(challenge.content.reads, 0)
                self.assertEqual(self.outcomes, Counter({"bot challenge": 1}))

    async def test_other_cookies_do_not_mark_a_page_as_challenge(self):
        page = await self.fetch(session_returning(response(200, "<html>ok</html>", [
            ("Set-Cookie", "anubis-theme=dark; Path=/"), ("Set-Cookie", "session=1; Path=/")])))
        self.assertEqual(page.text, "<html>ok</html>")
        self.assertEqual(self.outcomes, Counter({"ok": 1}))

    async def test_challenge_headers_on_a_normal_page_do_not_skip_it(self):
        page = await self.fetch(session_returning(response(200, "<html>ok</html>", {"x-kpsdk-ct": "token"})))
        self.assertEqual(page.text, "<html>ok</html>")
        self.assertEqual(self.outcomes, Counter({"ok": 1}))


class BlockedLoopTests(unittest.IsolatedAsyncioTestCase):
    async def test_connection_that_finished_while_the_loop_was_blocked_is_retried(self):
        # CPU-bound work in the worker's loop (parsing, matching) can outlast sock_connect. The connection
        # completes in time, but the expired timer runs first, so aiohttp reports a connect timeout.
        app = web.Application()
        app.router.add_get("/", lambda request: web.Response(text="ok"))
        runner = web.AppRunner(app)
        await runner.setup()
        self.addAsyncCleanup(runner.cleanup)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        await web.SockSite(runner, listener).start()
        url = "http://127.0.0.1:%d/" % listener.getsockname()[1]

        loop = asyncio.get_running_loop()
        connect = loop.sock_connect
        blocked = []

        async def connect_then_block(sock, address):
            # The TCP connection succeeds; then the loop is held inside the sock_connect window, as by a
            # long parse or match in another task. Only the first connection is held.
            await connect(sock, address)
            if not blocked:
                blocked.append(address)
                time.sleep(0.5)

        timeout = aiohttp.ClientTimeout(total=10, sock_read=5, sock_connect=0.2)
        for retries, expected in ((0, Counter({"connect timeout": 1})), (1, Counter({"ok": 1}))):
            with self.subTest(connect_retries=retries), patch.object(loop, "sock_connect", connect_then_block):
                blocked.clear()
                outcomes = Counter()
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True), timeout=timeout) as session:
                    await fetch_text(session, url, {}, outcomes=outcomes, connect_retries=retries)
                self.assertEqual(outcomes, expected)
                self.assertEqual(len(blocked), 1)


class LargeHeaderTests(unittest.IsolatedAsyncioTestCase):
    # A production page sent an 8,249-byte Content-Security-Policy header. aiohttp rejects any header line over
    # 8,190 bytes by default with a ClientResponseError, so the page, its links and its resources were lost.
    async def test_page_with_a_long_header_field_is_read(self):
        from credentialthreat.core.fetch import website_session

        app = web.Application()
        app.router.add_get("/", lambda request: web.Response(
            text="<html>ok</html>", content_type="text/html",
            headers={"Content-Security-Policy": "script-src " + "'sha256-x' " * 1000}))
        runner = web.AppRunner(app)
        await runner.setup()
        self.addAsyncCleanup(runner.cleanup)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        await web.SockSite(runner, listener).start()
        url = "http://127.0.0.1:%d/" % listener.getsockname()[1]

        outcomes = Counter()
        async with website_session(aiohttp.TCPConnector(force_close=True), aiohttp.ClientTimeout(total=10)) as session:
            page = await fetch_text(session, url, {}, outcomes=outcomes)
        self.assertEqual(outcomes, Counter({"ok": 1}))
        self.assertEqual(page.text, "<html>ok</html>")

    async def test_every_website_stage_opens_its_session_with_the_long_header_limits(self):
        from credentialthreat.core.credentialsearch import ScanerCredentials
        from credentialthreat.core.internallinksearch import ScanerInternalLinks
        from credentialthreat.core.networksearch import ScanerNetworkResources
        from credentialthreat.core.website import SUFFIXES

        stages = {
            "links": lambda: ScanerInternalLinks().process_internal_links(fqdns=[], tld_extract=SUFFIXES),
            "pages": lambda: ScanerNetworkResources().process_network_sources(
                network_points=[], domains_input=[], tld_extract=SUFFIXES),
            "resources": lambda: ScanerCredentials().process_credentials(network_files=[]),
        }
        original = aiohttp.ClientSession.__init__
        for stage, run in stages.items():
            with self.subTest(stage=stage):
                opened = []

                def record(session, *args, **kwargs):
                    opened.append(kwargs)
                    original(session, *args, **kwargs)

                with patch.object(aiohttp.ClientSession, "__init__", record):
                    await run()
                self.assertEqual(len(opened), 1)
                self.assertGreaterEqual(opened[0].get("max_field_size", 8190), 9000)
                self.assertGreaterEqual(opened[0].get("max_line_size", 8190), 9000)


if __name__ == "__main__":
    unittest.main()
