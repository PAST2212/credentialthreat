#!/usr/bin/env python3

import asyncio
from html import unescape
from urllib.parse import urljoin
import logging
from typing import Union
import warnings
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from bs4 import XMLParsedAsHTMLWarning
import aiohttp
import tldextract
from collections import Counter
from credentialthreat.core.fetch import HostPacer, fetch_text, get_header
from credentialthreat.core.interrupt_handler import AsyncCancellationManager
from credentialthreat.core.website import PublicDestinationConnector, canonical_url, is_binary_url
from aiolimiter import AsyncLimiter

logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


class ScanerInternalLinks:
    def __init__(self, max_concurrent_requests: int = 25, window_size: int = 50, scope=(),
                 host_connections: int | None = None) -> None:
        self.max_concurrent_requests = max_concurrent_requests
        self.host_connections = host_connections or max_concurrent_requests  # this worker's share
        self.window_size = window_size  # requests in flight per worker process
        self.rate_limiter = AsyncLimiter(max_concurrent_requests, 1)
        self.pacer = HostPacer(rate=max_concurrent_requests, connections=self.host_connections)  # per host: pacing, 429/503 backoff, request slots
        self.scope = tuple(scope)
        self.cancellation_manager = AsyncCancellationManager()
        self.outcomes: Counter = Counter()

    async def _get_request(self, url: str, header: dict, session: aiohttp.ClientSession) -> Union[tuple[str, BeautifulSoup], None]:
        """Final page URL and parsed HTML, or None when the page could not be read."""
        page = await fetch_text(session, url, header, scope=self.scope, limiter=self.rate_limiter,
                                pacer=self.pacer, outcomes=self.outcomes)
        if page is None:
            return None
        return page.url, BeautifulSoup(page.text, 'html.parser')

    @staticmethod
    def _process_link(link: str, page_url: str) -> Union[str, None]:
        """Resolve an href against the page it appeared on; only fetchable, non-binary pages remain."""
        try:
            link = unescape(link.strip())
            if not link:
                return None
            url = canonical_url(urljoin(page_url, link))
        except (AttributeError, ValueError):
            return None
        if url is None or is_binary_url(url):
            return None
        return url

    async def _fetch_internal_links(self, domain: str, tld_extract: tldextract.tldextract.TLDExtract, header: dict, session: aiohttp.ClientSession):
        results: set = set()
        try:
            if fetched := await self._get_request('https://' + domain + '/', header, session):
                page_url, soup = fetched
                results.add(page_url)
                for anchor in soup.find_all('a'):
                    href = anchor.get("href")
                    if href:
                        if processed_link := self._process_link(href, page_url):
                            results.add(processed_link)
        except Exception as e:
            logger.error("Internal link processing failed (%s)", type(e).__name__)

        return results

    async def process_internal_links(self, fqdns: list[str], tld_extract: tldextract.tldextract.TLDExtract):
        connector = PublicDestinationConnector(
            limit_per_host=self.host_connections,
            force_close=False,
            keepalive_timeout=300,
            enable_cleanup_closed=True,
            ttl_dns_cache=600
        )
        timeout = aiohttp.ClientTimeout(total=45, sock_read=30, sock_connect=5)
        header = get_header()

        all_results: set = set()
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                results = await self.cancellation_manager.run_window(
                    fqdns, lambda fqdn: self._fetch_internal_links(fqdn, tld_extract, header, session), self.window_size)
                all_results = {link for links in results if isinstance(links, set) for link in links}

        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.info("Operation cancelled, cleaning up...")
            await self.cancellation_manager.cancel_all()
        finally:
            await connector.close()

        return all_results

    async def get_results(self, fqdns: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> tuple[set[str], dict[str, int]]:
        """Links found on the hosts' start pages and the request outcome counts."""
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        results = await self.process_internal_links(fqdns=fqdns, tld_extract=tld_extract)
        return results, dict(self.outcomes)
