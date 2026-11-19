"""Aggregate counts of existing public scans ending on the exact input host."""

from datetime import timedelta

from credentialthreat.core.discovery import UnexpectedFormat


NAME = "urlscan.io"
QUOTA_URL = "https://urlscan.io/user/quotas/"


def request(domain, until):
    since = until - timedelta(days=30)
    query = f'page.domain.keyword:"{domain}" AND date:[{since}T00:00:00Z TO {until}T00:00:00Z' + '}'
    return "https://urlscan.io/api/v1/search/", {"q": query, "size": 1}


def count(payload, domain):
    if not isinstance(payload, dict):
        raise UnexpectedFormat
    total, rows, more = payload.get("total"), payload.get("results"), payload.get("has_more")
    if type(total) is not int or not 0 <= total <= 10000 or type(more) is not bool or not isinstance(rows, list):
        raise UnexpectedFormat
    if len(rows) != min(total, 1) or (more and total != 10000):
        raise UnexpectedFormat
    if rows:
        page = rows[0].get("page") if isinstance(rows[0], dict) else None
        if not isinstance(page, dict) or not isinstance(page.get("domain"), str):
            raise UnexpectedFormat
        if page["domain"].lower().rstrip(".") != domain:
            raise UnexpectedFormat
    return total, "at_least" if more else "exact"


def search_quotas(payload):
    try:
        quotas = payload["limits"]["search"]
        for window in ("minute", "hour", "day"):
            limit, remaining = quotas[window]["limit"], quotas[window]["remaining"]
            if type(limit) is not int or type(remaining) is not int or not 0 <= remaining <= limit:
                raise UnexpectedFormat
    except (KeyError, TypeError) as exc:
        raise UnexpectedFormat from exc
    return quotas
