#!/usr/bin/env python3

import json

import aiohttp
from credentialthreat.core.discovery import SubdomainProvider, UnexpectedFormat, require_ok
from credentialthreat.core.website import host_in_scope


class ScanerAnubisDb(SubdomainProvider):
    """AnubisDB, a free subdomain database that recon tools submit their findings to.

    The scanner only reads from it. It never submits the names it discovers.
    """
    name = "AnubisDB"
    retry_pause = 5.0  # published limit: 60 requests per 10 seconds
    query_interval = 0.2

    @staticmethod
    async def _scrape_subdomains(session: aiohttp.ClientSession, domain: str) -> tuple[int, set[str]]:
        async with session.get(f"https://anubisdb.com/subdomains/{domain}") as response:
            require_ok(response.status)
            entries = json.loads(await response.text())
        # A domain without data is an empty list.
        if not isinstance(entries, list) or not all(isinstance(entry, str) for entry in entries):
            raise UnexpectedFormat
        names = set()
        for entry in entries:
            host = entry.strip().lower().removeprefix("*.")
            if host_in_scope(host, [domain]):
                names.add(host)
        return len(entries), names
