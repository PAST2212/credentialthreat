#!/usr/bin/env python3

import json

import aiohttp
from credentialthreat.core.discovery import SubdomainProvider, UnexpectedFormat, require_ok
from credentialthreat.core.website import host_in_scope


class ScanerCrtsh(SubdomainProvider):
    name = "crt.sh"

    @staticmethod
    async def _scrape_subdomains(session: aiohttp.ClientSession, domain: str) -> tuple[int, set[str]]:
        params = {"q": f"%.{domain}", "output": "json"}
        async with session.get("https://crt.sh/", params=params) as response:
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
