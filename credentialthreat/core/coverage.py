"""Count public observations without passing provider data to the website scanner."""

import asyncio
import csv
from datetime import datetime, timedelta, timezone
import sys

import aiohttp

from credentialthreat.core.discovery import HttpStatusError, error_reason, require_ok
from credentialthreat.core.website import PublicDestinationConnector
from credentialthreat.recon import mnemonic, urlscan


PROVIDERS = (mnemonic, urlscan)


def utcnow():
    return datetime.now(timezone.utc)


class QuotaLimit(HttpStatusError):
    def __init__(self, status, delay):
        super().__init__(status)
        self.delay = delay


async def fetch(session, url, params, end):
    seconds_left = (end - utcnow()).total_seconds()
    if seconds_left <= 0:
        raise TimeoutError
    async with asyncio.timeout(min(20, seconds_left)):
        async with session.get(url, params=params, allow_redirects=False) as response:
            if response.status in (402, 429):
                delay = None
                if response.status == 402:
                    try:
                        metadata = (await response.json())["metaData"]
                        millis = metadata["millisUntilResourcesAvailable"]
                        if type(millis) is int and millis >= 0:
                            delay = min(millis, 3600000) / 1000
                    except (ValueError, KeyError, TypeError, aiohttp.ContentTypeError):
                        pass
                else:
                    for header in ("Retry-After", "X-Rate-Limit-Reset-After"):
                        value = response.headers.get(header, "")
                        if value.isascii() and value.isdecimal():
                            delay = min(int(value), 3600)
                            break
                raise QuotaLimit(response.status, delay)
            require_ok(response.status)
            return await response.json(), response.headers


async def collect(provider, session, domains, samples, start, end, writer):
    requested = len(domains) * samples
    stop = ""
    ready = start
    period = start.replace(second=0, microsecond=0)
    per_minute = mnemonic.PER_MINUTE
    minute_left = per_minute
    budget = mnemonic.PER_DAY
    if provider is urlscan:
        try:
            raw, _ = await fetch(session, urlscan.QUOTA_URL, None, end)
            quotas = urlscan.search_quotas(raw)
            print("urlscan.io search limits: " + ", ".join(
                f"{quotas[k]['limit']}/{unit} ({quotas[k]['remaining']} remaining)"
                for k, unit in (("minute","min"), ("hour","hour"), ("day","day"))
            ), file=sys.stderr, flush=True)
            per_minute = quotas["minute"]["limit"]
            period = utcnow().replace(second=0, microsecond=0)
            minute_left = quotas["minute"]["remaining"]
            budget = min(quotas["hour"]["remaining"], quotas["day"]["remaining"])
        except Exception as exc:
            stop = "quota unavailable: " + error_reason(provider.NAME, exc)
    else:
        print(f"mnemonic public limits: {per_minute}/min, {budget}/day; hourly limit unpublished",
              file=sys.stderr, flush=True)

    complete = True
    for index in range(requested):
        domain = domains[index % len(domains)]
        sample = index // len(domains) + 1
        now = utcnow()
        if index >= budget or not per_minute:
            stop = stop or "quota exhausted"
        earliest = max(ready, now)
        if minute_left == 0:
            earliest = max(earliest, period + timedelta(minutes=1))
        if earliest >= end:
            stop = stop or "hour window ended"
        if not stop and earliest > now:
            await asyncio.sleep((earliest - now).total_seconds())
        now = utcnow()
        if now >= end:
            stop = stop or "hour window ended"
        status, count, relation, reason = "skipped", "", "", stop
        if not stop:
            current_minute = now.replace(second=0, microsecond=0)
            if current_minute != period:
                minute_left, period = per_minute, current_minute
            minute_left -= 1
            ready = now + timedelta(seconds=60 / per_minute + 0.1)
            url, params = provider.request(domain, start.date())
            try:
                data, headers = await fetch(session, url, params, end)
                if provider is urlscan and headers.get("X-Rate-Limit-Remaining") == "0":
                    if headers.get("X-Rate-Limit-Window") == "minute":
                        period = utcnow().replace(second=0, microsecond=0)
                        minute_left = 0
                    elif headers.get("X-Rate-Limit-Window") in ("hour", "day"):
                        stop = "quota exhausted"
                count, relation = provider.count(data, domain)
                status = "hits" if count else "empty"
            except Exception as exc:
                status, reason = "errors", error_reason(provider.NAME, exc)
                if isinstance(exc, QuotaLimit):
                    if exc.delay is None:
                        stop = reason + " quota limit"
                    else:
                        ready = max(ready, utcnow() + timedelta(seconds=exc.delay))
        writer.writerow((now.isoformat(timespec="seconds"), sample, domain, provider.NAME,
                         status, count, relation, reason))
        sys.stdout.flush()
        if status in ("errors", "skipped"):
            complete = False
    return complete


async def run_coverage(domains, samples, source=None):
    domains = list(dict.fromkeys(domains))
    providers = [p for p in PROVIDERS if source is None or p.NAME == source]
    start = utcnow()
    end = start.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    print(f"urlscan.io UTC search dates: [{start.date() - timedelta(days=30)}, {start.date()}); "
          f"measurement stops by {end.isoformat(timespec='minutes')}", file=sys.stderr, flush=True)
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(("timestamp_utc", "sample", "domain", "source", "status", "count", "relation", "reason"))
    async with aiohttp.ClientSession(connector=PublicDestinationConnector(),
                                     cookie_jar=aiohttp.DummyCookieJar()) as session:
        # aiohttp 3.11 retries a disconnected GET internally, which would duplicate a sample.
        session._retry_connection = False
        results = await asyncio.gather(*(collect(provider, session, domains, samples, start, end, writer)
                                         for provider in providers))
    return 0 if all(results) else 1
