#!/usr/bin/env python3

import asyncio
import json

import aiohttp
from credentialthreat.core.discovery import SubdomainProvider, UnexpectedFormat, require_ok
from credentialthreat.core.website import canonical_url, is_binary_url, url_in_scope

URL_LIST = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"


class ScanerOtxUrls(SubdomainProvider):
    """Page URLs that AlienVault OTX has seen under a domain. They go to the page stage, not to link discovery.

    Link discovery finds only pages that a start page links to. On a large retailer, 146 of 200 OTX URLs that the
    crawl had never requested were readable pages. The URL list answers without an API key, but OTX publishes no
    limit for that, and deep pages are slow: one took 60 s and ended with HTTP 504. So only the first pages are read,
    and a failing later page keeps the URLs already read; the summary then reports the answer as partial.
    """
    name = "AlienVault OTX"
    kind = "urls"
    retry_pause = 5.0
    max_pages = 4
    page_size = 500
    page_pause = 1.0  # seconds between two pages

    @classmethod
    async def _scrape_subdomains(cls, session: aiohttp.ClientSession, domain: str) -> tuple[int, set[str], int | None]:
        records, urls, stated = 0, set(), None
        for page in range(1, cls.max_pages + 1):
            if page > 1:
                await asyncio.sleep(cls.page_pause)
            try:
                rows, has_next, full_size = await cls._page(session, domain, page)
            except Exception:
                if page == 1:
                    raise
                break
            stated = full_size if page == 1 else stated
            records += len(rows)
            for row in rows:
                url = canonical_url(row)
                if url and url_in_scope(url, [domain]) and not is_binary_url(url):
                    urls.add(url)
            if not has_next:
                break
        return records, urls, stated

    @classmethod
    async def _page(cls, session: aiohttp.ClientSession, domain: str, page: int) -> tuple[list[str], bool, int | None]:
        async with session.get(URL_LIST.format(domain=domain), params={"limit": cls.page_size, "page": page}) as response:
            require_ok(response.status)
            data = json.loads(await response.text())
        if not isinstance(data, dict) or not isinstance(data.get("url_list"), list) or type(data.get("has_next")) is not bool:
            raise UnexpectedFormat
        rows = []
        for row in data["url_list"]:
            url = row.get("url") if isinstance(row, dict) else None
            if not isinstance(url, str):
                raise UnexpectedFormat
            rows.append(url)
        full_size = data.get("full_size")
        return rows, data["has_next"], full_size if type(full_size) is int and full_size >= 0 else None
