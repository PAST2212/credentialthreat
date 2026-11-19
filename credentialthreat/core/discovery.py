"""Outcomes of individual discovery queries; only counts and fixed diagnostics are logged."""

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


async def observe(provider: str, domain: str, query: Awaitable[tuple[int, set[str]]]) -> QueryResult:
    try:
        records, values = await query
        return QueryResult(provider, domain, records, frozenset(values))
    except Exception as exc:
        return QueryResult(provider, domain, None, reason=error_reason(provider, exc))


def combined_values(results: Iterable[QueryResult]) -> set[str]:
    return {value for result in results for value in result.values}


class SubdomainProvider:
    name: str

    def __init__(self):
        self.results: set[str] = set()

    async def _scrape_subdomains(self, session, domain) -> tuple[int, set[str]]:
        raise NotImplementedError

    async def get_report(self, domains, session) -> list[QueryResult]:
        return [await observe(self.name, domain, self._scrape_subdomains(session, domain)) for domain in domains]

    async def get_results(self, domains, session) -> set[str]:
        self.results.update(combined_values(await self.get_report(domains, session)))
        return self.results


def log_query_summary(results: list[QueryResult]) -> bool:
    """Log per-provider query counts and return whether any query failed."""
    counts = {}
    reasons = {}
    for result in results:
        counts.setdefault(result.provider, Counter())[result.state] += 1
        if result.reason is not None:
            reasons.setdefault(result.provider, Counter())[result.reason] += 1
    for provider, count in counts.items():
        detail = ", ".join(f"{reason}={n}" for reason, n in sorted(reasons.get(provider, {}).items()))
        logging.log(logging.WARNING if count["error"] else logging.INFO,
                    "%s: hits=%d empty=%d filtered=%d errors=%d%s", provider,
                    count["hits"], count["empty"], count["filtered"], count["error"],
                    f" ({detail})" if detail else "")
    return bool(reasons)
