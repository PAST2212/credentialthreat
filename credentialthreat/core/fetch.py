"""HTTP request helpers shared by the website scan stages."""

import asyncio
from collections import Counter
import contextlib
from dataclasses import dataclass
from datetime import datetime, timezone
import email.utils
import logging
import random
import re
import time
from urllib.parse import urljoin, urlsplit

import aiohttp

from credentialthreat.core.website import DestinationBlocked, canonical_url, url_in_scope


logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 10 * 2**20
MAX_REDIRECTS = 3
MAX_ATTEMPTS = 3
RETRY_STATUSES = frozenset({429, 503})
MAX_RETRY_DELAY = 30.0
CHUNK_BYTES = 64 * 1024
# SVG is XML text and can carry script, so it stays readable.
BINARY_CONTENT = re.compile(
    r"(image/(?!svg)|audio/|video/|font/|application/(pdf|zip|gzip|x-gzip|x-tar|x-rar|x-7z|octet-stream"
    r"|vnd\.ms-|msword|vnd\.openxmlformats|wasm))", re.IGNORECASE)


class HostPacer:
    """Per-host request pacing inside one worker process (additive increase, multiplicative decrease).

    Each host starts at ``rate`` requests per second. A 429/503 pauses every request to that host
    for the announced delay and halves its rate (not below ``floor``). Each other response raises
    the rate by a small step, never above the start. Several workers that back off independently
    therefore settle below a server's limit instead of multiplying the load on it.
    """

    def __init__(self, rate: float = 25.0, floor: float = 0.5, clock=time.monotonic, sleep=None,
                 connections: int | None = None):
        self.start = rate
        self.floor = floor
        self.clock = clock
        self.sleep = sleep
        self.connections = connections  # requests per host at once; None means unlimited
        self.rates: dict[str, float] = {}
        self.next_slot: dict[str, float] = {}
        self.paused_until: dict[str, float] = {}
        self._in_flight: dict[str, asyncio.Semaphore] = {}

    @contextlib.asynccontextmanager
    async def slot(self, host: str):
        """Hold one of the host's request slots, then wait for its next pacing slot.

        Waiting here, outside the HTTP client, keeps queued requests from using up their
        timeout, which aiohttp also counts while a request waits for a pooled connection.
        """
        if not self.connections:
            await self.wait(host)
            yield
            return
        semaphore = self._in_flight.setdefault(host, asyncio.Semaphore(self.connections))
        async with semaphore:
            await self.wait(host)
            yield

    async def wait(self, host: str) -> None:
        sleep = self.sleep or asyncio.sleep
        while True:
            now = self.clock()
            slot = max(now, self.next_slot.get(host, now), self.paused_until.get(host, now))
            if slot <= now:
                self.next_slot[host] = now + 1.0 / self.rates.get(host, self.start)
                return
            await sleep(slot - now)

    def throttled(self, host: str, delay: float) -> None:
        self.rates[host] = max(self.floor, self.rates.get(host, self.start) / 2)
        self.paused_until[host] = max(self.paused_until.get(host, 0.0), self.clock() + delay)

    def succeeded(self, host: str) -> None:
        rate = self.rates.get(host, self.start)
        if rate < self.start:
            self.rates[host] = min(self.start, rate + self.start / 32)


def is_bot_challenge(status: int, headers) -> bool:
    """True for an error response that a bot-management service marks as a challenge instead of content.

    Kasada sends its challenge with an ``x-kpsdk-ct`` token, Cloudflare with ``cf-mitigated: challenge``.
    A challenge page only loads the service's script, which is fetched anew under a unique URL every time.
    """
    if 200 <= status < 300:
        return False
    return "x-kpsdk-ct" in headers or (headers.get("cf-mitigated") or "").strip().lower() == "challenge"


def connection_failure(exc: Exception) -> str:
    """Outcome name for a request that never got a response, by cause (no exception text)."""
    if isinstance(exc, aiohttp.ClientConnectorDNSError):
        return "destination blocked" if isinstance(exc.os_error, DestinationBlocked) else "DNS"
    if isinstance(exc, aiohttp.ClientSSLError):  # includes certificate errors
        return "TLS"
    return "connection"


@dataclass(frozen=True)
class Page:
    url: str  # final URL after in-scope redirects
    status: int
    text: str
    content_type: str = ""


def retry_delay(headers, attempt: int) -> float:
    """Seconds announced by Retry-After (seconds or HTTP date), else exponential backoff; capped."""
    value = (headers.get("Retry-After") or "").strip()
    delay = None
    if value.isascii() and value.isdigit():
        delay = float(value)
    elif value:
        try:
            delay = (email.utils.parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError):
            delay = None
    if delay is None or delay < 0:
        delay = 2.0 ** attempt
    return min(delay, MAX_RETRY_DELAY)


def _redirect_target(url: str, location: str | None, scope) -> str | None:
    if not location or not scope:
        return None
    target = canonical_url(urljoin(url, location))
    return target if target and url_in_scope(target, scope) else None


async def _read_text(response, max_bytes: int) -> tuple[str, bool]:
    body = bytearray()
    truncated = False
    async for chunk in response.content.iter_chunked(CHUNK_BYTES):
        body += chunk
        if len(body) > max_bytes:
            del body[max_bytes:]
            truncated = True
            break
    return body.decode("utf-8", "ignore"), truncated


async def fetch_text(session, url: str, headers: dict, *, scope=(), limiter=None, pacer: HostPacer | None = None,
                     outcomes: Counter | None = None, sleep=None, max_bytes: int = MAX_BODY_BYTES,
                     connect_retries: int = 0) -> Page | None:
    """GET a text resource without automatic redirects.

    Redirects are followed only to URLs inside ``scope`` (at most MAX_REDIRECTS hops); every hop
    goes through the same connector checks. 429/503 and read timeouts are retried, connect timeouts
    up to ``connect_retries`` times. Bot challenges and binary content types are not downloaded, and
    bodies are cut at ``max_bytes``. Error-status bodies are returned for scanning but counted as
    ``HTTP <status> read``, not ``ok``. Each call adds exactly one entry to ``outcomes``.
    """
    outcomes = outcomes if outcomes is not None else Counter()
    sleep = sleep or asyncio.sleep
    connect_timeouts = 0
    for _hop in range(MAX_REDIRECTS + 1):
        attempt = 0
        while True:
            attempt += 1
            wait = None
            host = urlsplit(url).hostname or ""
            try:
                # The host slot is held only for this attempt; retries wait for it again.
                async with pacer.slot(host) if pacer is not None else contextlib.nullcontext():
                    if limiter is not None:
                        async with limiter:
                            pass
                    async with session.get(url, headers=headers, allow_redirects=False) as response:
                        status = response.status
                        if is_bot_challenge(status, response.headers):
                            # The challenge holds no site content, and repeating the request does not pass it.
                            outcomes["bot challenge"] += 1
                            return None
                        if status in RETRY_STATUSES:
                            delay = retry_delay(response.headers, attempt)
                            if pacer is not None:
                                pacer.throttled(host, delay)  # the next attempt waits in pacer.wait
                            if attempt >= MAX_ATTEMPTS:
                                outcomes[f"HTTP {status}"] += 1
                                return None
                            wait = 0.0 if pacer is not None else delay
                        else:
                            if pacer is not None:
                                pacer.succeeded(host)
                            if 300 <= status < 400:
                                target = _redirect_target(url, response.headers.get("Location"), scope)
                                if target is None:
                                    outcomes["redirect skipped"] += 1
                                    return None
                                url = target
                                break
                            content_type = (response.headers.get("Content-Type") or "").strip()
                            if BINARY_CONTENT.match(content_type):
                                outcomes["binary"] += 1
                                return None
                            text, truncated = await _read_text(response, max_bytes)
                            if 200 <= status < 300:
                                outcomes["truncated" if truncated else "ok"] += 1
                            else:
                                outcomes[f"HTTP {status} read"] += 1
                            return Page(url, status, text, content_type.lower())
            except aiohttp.ConnectionTimeoutError:
                # A host that did not accept a connection rarely does on a second try. But when CPU-bound
                # work blocks the event loop past sock_connect, a connection that succeeded ends the same way.
                connect_timeouts += 1
                if connect_timeouts > connect_retries:
                    outcomes["connect timeout"] += 1
                    return None
                attempt -= 1  # the retry does not use up the attempts for 429/503 and read timeouts
            except (asyncio.TimeoutError, aiohttp.ServerDisconnectedError, aiohttp.ClientPayloadError) as exc:
                if attempt >= MAX_ATTEMPTS:
                    outcomes["timeout" if isinstance(exc, asyncio.TimeoutError) else "connection"] += 1
                    return None
                wait = 2.0 ** attempt
            except (aiohttp.ClientConnectionError, aiohttp.InvalidURL) as exc:
                outcomes[connection_failure(exc)] += 1
                return None
            except Exception as exc:
                logger.error("Website request failed (%s)", type(exc).__name__)
                outcomes["error"] += 1
                return None
            if wait:
                await sleep(wait)
    outcomes["too many redirects"] += 1
    return None


def get_header() -> dict:
    user_agents = [
        'Mozilla/5.0 (Linux; Android 10; LM-Q730) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 11; SM-A115F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 12; M2101K7AG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 9; INE-LX2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; CPH2179) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35',
        'Mozilla/5.0 (Linux; Android 12; motorola edge 5G UW (2021)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 9; SM-J530F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36',
        'Mozilla/5.0 (Android 10; Mobile; rv:109.0) Gecko/113.0 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.54 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.106 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; CPH1819) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 11; A509DL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 11; SM-A207M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 12; SM-M515F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; HRY-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Linux; Android 11; moto g pure) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35',
        'Mozilla/5.0 (Linux; Android 10; CPH1931) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; Infinix X656) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 11; SM-A207F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; JSN-L21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 12; SM-S127DL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Linux; Android 12; SM-A135U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.25 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Linux; Android 12; FNE-NX9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Android 11; Mobile; rv:109.0) Gecko/113.0 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36',
        'Mozilla/5.0 (Android 12; Mobile; rv:109.0) Gecko/113.0 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35',
        'Mozilla/5.0 (Linux; Android 10; SM-N960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; Lenovo TB-8505F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 12; SM-A115F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; M2004J19C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 13; SM-A536E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; ELE-L29) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; COL-L29) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.3; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/113.0 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0'
    ]

    headers = {
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': random.choice(user_agents)
    }

    return headers
