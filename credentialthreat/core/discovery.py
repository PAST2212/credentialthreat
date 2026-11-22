"""Outcomes of individual discovery queries; only counts and fixed diagnostics are logged."""

import asyncio
from collections import Counter
from collections.abc import Awaitable, Iterable
from dataclasses import dataclass, field
from json import JSONDecodeError
import logging
import socket

import aiohttp

from credentialthreat.core.diagnostics import log_discovery_error
from credentialthreat.core.website import DestinationBlocked


@dataclass(frozen=True)
class QueryResult:
    provider: str
    domain: str = field(repr=False)
    records: int | None
    values: frozenset[str] = field(default_factory=frozenset, repr=False)
    reason: str | None = None
    available: int | None = None  # records the provider states it holds; above `records`, the answer is partial
    kind: str = "hosts"  # what `values` holds: host names, or page URLs ("urls") for the page stage

    @property
    def partial(self) -> bool:
        """The provider states more records than it returned (for example without an account)."""
        return self.available is not None and self.records is not None and self.available > self.records

    @property
    def state(self) -> str:
        if self.reason is not None:
            return "error"
        if self.values:
            return "hits"
        return "empty" if self.records == 0 else "filtered"


class UnexpectedFormat(ValueError):
    pass


class HttpStatusError(Exception):
    def __init__(self, status: int):
        self.status = status


def require_ok(status: int) -> None:
    if status != 200:
        raise HttpStatusError(status)


def error_reason(provider: str, exc: Exception) -> str:
    if isinstance(exc, HttpStatusError):
        logging.warning("%s returned HTTP %d", provider, exc.status)
        return f"HTTP {exc.status}"
    if isinstance(exc, aiohttp.ClientConnectorDNSError) and isinstance(exc.os_error, DestinationBlocked):
        log_discovery_error(provider, exc.os_error)
        return "destination blocked"
    log_discovery_error(provider, exc)
    if isinstance(exc, (aiohttp.ClientConnectorDNSError, socket.gaierror)):
        return "DNS"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, (UnexpectedFormat, JSONDecodeError, UnicodeError, aiohttp.ContentTypeError)):
        return "unexpected format"
    if isinstance(exc, aiohttp.ClientResponseError) and exc.status:
        return f"HTTP {exc.status}"
    return type(exc).__name__


async def observe(provider: str, domain: str, query: Awaitable[tuple], kind: str = "hosts") -> QueryResult:
    """Run one provider query: (records, values) or (records, values, records the provider states it holds)."""
    try:
        records, values, *available = await query
        return QueryResult(provider, domain, records, frozenset(values), available=available[0] if available else None,
                           kind=kind)
    except Exception as exc:
        return QueryResult(provider, domain, None, reason=error_reason(provider, exc), kind=kind)


def combined_values(results: Iterable[QueryResult]) -> set[str]:
    return {value for result in results for value in result.values}


class SubdomainProvider:
    name: str
    retry_pause: float = 15.0  # seconds before repeating a query that failed with a server error
    kind: str = "hosts"  # "urls" for a provider whose values are page URLs

    def __init__(self):
        self.results: set[str] = set()

    async def _scrape_subdomains(self, session, domain) -> tuple[int, set[str]]:
        raise NotImplementedError

    async def _query(self, session, domain) -> QueryResult:
        result = await observe(self.name, domain, self._scrape_subdomains(session, domain), self.kind)
        if result.reason is not None and result.reason.startswith("HTTP 5"):
            await asyncio.sleep(self.retry_pause)
            result = await observe(self.name, domain, self._scrape_subdomains(session, domain), self.kind)
        return result

    async def get_report(self, domains, session) -> list[QueryResult]:
        return [await self._query(session, domain) for domain in domains]

    async def get_results(self, domains, session) -> set[str]:
        self.results.update(combined_values(await self.get_report(domains, session)))
        return self.results


def log_query_summary(results: list[QueryResult]) -> bool:
    """Log per-provider query counts and return whether any query failed.

    A partial answer (the provider states more records than it returned) is a warning, not a failure:
    it is how some providers answer without an account, so it would otherwise fail every large scan.
    """
    counts = {}
    reasons = {}
    partial = {}
    for result in results:
        counts.setdefault(result.provider, Counter())[result.state] += 1
        if result.reason is not None:
            reasons.setdefault(result.provider, Counter())[result.reason] += 1
        if result.partial:
            queries, returned, stated = partial.get(result.provider, (0, 0, 0))
            partial[result.provider] = (queries + 1, returned + result.records, stated + result.available)
    for provider, count in counts.items():
        detail = ", ".join(f"{reason}={n}" for reason, n in sorted(reasons.get(provider, {}).items()))
        part = partial.get(provider)
        logging.log(logging.WARNING if count["error"] or part else logging.INFO,
                    "%s: hits=%d empty=%d filtered=%d errors=%d%s%s", provider,
                    count["hits"], count["empty"], count["filtered"], count["error"],
                    f" ({detail})" if detail else "",
                    f", partial={part[0]} ({part[1]} of {part[2]} records)" if part else "")
    return bool(reasons)
