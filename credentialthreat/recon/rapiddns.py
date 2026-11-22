#!/usr/bin/env python3

import re

import aiohttp
from bs4 import BeautifulSoup
from credentialthreat.core.discovery import SubdomainProvider, UnexpectedFormat, require_ok
from credentialthreat.core.website import host_in_scope

TOTAL_LABEL = re.compile(r"^\s*Total:\s*$")


def _stated_total(soup: BeautifulSoup) -> int | None:
    """The record count RapidDNS states above its table. Without an account the table lists only 100 of them."""
    label = soup.find(string=TOTAL_LABEL)
    count = label.parent.find("span") if label else None  # only the count beside the label, never a later number
    text = count.get_text(strip=True).replace(",", "") if count else ""
    return int(text) if text.isdigit() else None


class ScanerRapidDns(SubdomainProvider):
    name = "RapidDNS"
    retry_pause = 5.0  # published limit: 30 requests per minute
    query_interval = 2.0

    @staticmethod
    async def _scrape_subdomains(session: aiohttp.ClientSession, domain: str) -> tuple[int, set[str], int | None]:
        url = f"https://rapiddns.io/s/{domain}?full=1#result"
        async with session.get(url) as response:
            require_ok(response.status)
            soup = BeautifulSoup(await response.text(), "lxml")
        table = soup.find("table", id="table")
        rows = table.find_all("tr") if table else []
        if not rows:
            raise UnexpectedFormat
        columns = [th.get_text(strip=True).lower() for th in rows[0].find_all("th", recursive=False)]
        if not {"domain", "address", "type"}.issubset(columns):
            raise UnexpectedFormat
        domain_column = columns.index("domain")
        names = set()
        for row in rows[1:]:
            cells = row.find_all(["td", "th"], recursive=False)
            if len(cells) != len(columns) or not row.find("td", recursive=False):
                raise UnexpectedFormat
            host = cells[domain_column].get_text(strip=True)
            if not host:
                raise UnexpectedFormat
            if host_in_scope(host, [domain]):
                names.add(host)
        return len(rows) - 1, names, _stated_total(soup)
