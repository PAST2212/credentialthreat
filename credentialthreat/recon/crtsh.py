#!/usr/bin/env python3

import json

import aiohttp
from credentialthreat.core.discovery import SubdomainProvider, UnexpectedFormat, require_ok
from credentialthreat.core.website import host_in_scope

# crt.sh answers a domain with many certificates only after its database query, which took 14 to 64 s for a
# domain with 1,500 hosts. It ends a query itself with HTTP 504 after 120 s, so the client waits a little longer.
QUERY_TIMEOUT = aiohttp.ClientTimeout(total=150, connect=10)


class ScanerCrtsh(SubdomainProvider):
    name = "crt.sh"
    retry_pause = 15.0  # published limit: 5 requests per minute

    @staticmethod
    async def _scrape_subdomains(session: aiohttp.ClientSession, domain: str) -> tuple[int, set[str]]:
        params = {"q": f"%.{domain}", "output": "json"}
        async with session.get("https://crt.sh/", params=params, timeout=QUERY_TIMEOUT) as response:
            require_ok(response.status)
            certificates = json.loads(await response.text())
        if not isinstance(certificates, list):
            raise UnexpectedFormat
        names = set()
        for certificate in certificates:
            names_field = certificate.get("name_value") if isinstance(certificate, dict) else None
            if not isinstance(names_field, str) or not names_field.strip():
                raise UnexpectedFormat
            for entry in names_field.splitlines():
                host = entry.lower().removeprefix("*.")
                if host_in_scope(host, [domain]):
                    names.add(host)
        return len(certificates), names
