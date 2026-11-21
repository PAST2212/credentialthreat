#!/usr/bin/env python3

import re
import asyncio
from dataclasses import dataclass
import logging
import warnings
from typing import Union
import tldextract
import json
from collections import Counter
import aiohttp
from aiolimiter import AsyncLimiter
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from bs4 import XMLParsedAsHTMLWarning
from credentialthreat.core.credentialsearch import ScanerCredentials
from credentialthreat.core.fetch import HostPacer, Page, fetch_text, get_header
from credentialthreat.core.interrupt_handler import AsyncCancellationManager
from credentialthreat.core.website import (PublicDestinationConnector, canonical_url, module_imports, report_origin,
                                           resolve_reference, url_in_scope)


logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


@dataclass
class ScrapNetworkUrls:
    origin_url: str
    script_url: str


class ScanerNetworkResources:
    def __init__(self, max_concurrent_requests: int = 25, window_size: int = 50, scope=(),
                 host_connections: int | None = None) -> None:
        self.pages: set[str] = set()  # page URLs requested here, read or not, including redirect targets
        self.matcher = ScanerCredentials()  # only its rules are used; it sends no requests
        self.max_concurrent_requests = max_concurrent_requests
        self.host_connections = host_connections or max_concurrent_requests  # this worker's share
        self.window_size = window_size  # requests in flight per worker process
        self.rate_limiter = AsyncLimiter(max_concurrent_requests, 1)
        self.pacer = HostPacer(rate=max_concurrent_requests, connections=self.host_connections)  # per host: pacing, 429/503 backoff, request slots
        self.cancellation_manager = AsyncCancellationManager()
        self.scope = tuple(scope)
        self.outcomes: Counter = Counter()

    @staticmethod
    def parse(page: Page) -> BeautifulSoup:
        """The page's markup for link and resource extraction."""
        markup = page.text
        # WordPress JSON API responses embed HTML with escaped URLs; re-serializing unescapes them.
        if 'application/json' in page.content_type:
            try:
                markup = f"<html><body>{json.dumps(json.loads(markup))}</body></html>"
            except json.JSONDecodeError:
                pass
        return BeautifulSoup(markup, 'html.parser')

    async def _get_request(self, url: str, header, session: aiohttp.ClientSession) -> Union[None, tuple[str, str, BeautifulSoup]]:
        """Final page URL, page text and parsed markup, or None when the page could not be read."""
        # Parsing or matching another page can block this worker's loop past sock_connect and turn a connection
        # that succeeded into a connect timeout, so retry once (a dead host costs one more connect timeout).
        page = await fetch_text(session, url, header, scope=self.scope, limiter=self.rate_limiter,
                                pacer=self.pacer, outcomes=self.outcomes, connect_retries=1)
        if page is None:
            return None
        return page.url, page.text, self.parse(page)

    @staticmethod
    def _clean_url(url: str) -> str:
        """ handle double-escaped URLs with backslashes """
        try:
            # Remove JSON escaping
            url = url.replace('\\"', '"').replace('\\/', '/')

            # Remove unnecessary escaping
            url = re.sub(r'\\+', '/', url)

            # Fix double slashes inside the path; keep the scheme separator and protocol-relative '//host'
            url = re.sub(r'(?<=[^:/])/{2,}', '/', url)

            # Remove any query params that look like JSON or escaped content
            url = re.sub(r'\?.*=\\.*', '', url)

            return url.strip('"\'')
        except Exception as e:
            logger.error("URL normalization failed (%s)", type(e).__name__)
            return url

    def _extract_url(self, element: BeautifulSoup, attr: str, base_url: str, domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> list[ScrapNetworkUrls]:
        results = []
        if url := element.attrs.get(attr):
            if full_url := resolve_reference(base_url, self._clean_url(url), domains_input):
                results.append(ScrapNetworkUrls(base_url, full_url))
        return results

    def scan_page(self, url: str, text: str, soup: BeautifulSoup, domains_input) -> tuple[list[ScrapNetworkUrls], list[tuple]]:
        """Resources a fetched page references, and the redacted candidates in its text."""
        results = []
        candidates = []
        if findings := self.matcher._findings(text):
            candidates.append((report_origin(url), report_origin(url), findings))

        for script in soup.find_all("script"):
            results.extend(self._extract_url(script, 'src', url, domains_input, None))
            results.extend(self._extract_url(script, 'data-src', url, domains_input, None))

        for resource in soup.find_all(['link', 'iframe', 'frame', 'embed', 'object']):
            for attr in ['href', 'src', 'data', 'data-src']:
                results.extend(self._extract_url(resource, attr, url, domains_input, None))

        for script in soup.find_all("script", src=None):  # inline scripts
            if script_text := script.string:
                # ES module imports, then the script loaders whose argument is a plain URL
                references = module_imports(script_text)
                for pattern in (r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
                                r'importScripts\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
                                r'loadScript\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)'):
                    references.extend(match.group(1) for match in re.finditer(pattern, script_text))
                for reference in references:
                    if imported_url := resolve_reference(url, reference, domains_input):
                        results.append(ScrapNetworkUrls(url, imported_url))
        return results, candidates

    async def _fetch_network_sources(self, url: str, domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract, header, session: aiohttp.ClientSession) -> tuple[list[ScrapNetworkUrls], list[tuple]]:
        """Resources the page references, and the redacted candidates in the page text itself.

        The page is fetched once here; the credential stage does not request it again.
        """
        results = []
        candidates = []
        try:
            url = canonical_url(self._clean_url(url)) or ""
            if not url_in_scope(url, domains_input):
                return results, candidates
            self.pages.add(url)
            fetched = await self._get_request(url, header, session)
            if fetched is not None:
                url, text, soup = fetched
                self.pages.add(url)
                results, candidates = self.scan_page(url, text, soup, domains_input)

        except Exception:
            self.pages.add(url)

        return results, candidates

    async def process_network_sources(self, network_points: list[str], domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> tuple[list[ScrapNetworkUrls], list[tuple]]:
        connector = PublicDestinationConnector(
            limit_per_host=self.host_connections,
            force_close=False,
            keepalive_timeout=300,
            enable_cleanup_closed=True,
            ttl_dns_cache=600
        )
        timeout = aiohttp.ClientTimeout(total=45, sock_read=30, sock_connect=5)
        header = get_header()

        all_results = []
        all_candidates = []
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                results = await self.cancellation_manager.run_window(
                    network_points,
                    lambda url: self._fetch_network_sources(url, domains_input, tld_extract, header, session),
                    self.window_size)
                scanned = [found for found in results if isinstance(found, tuple)]
                all_results = [item for resources, _ in scanned for item in resources]
                all_candidates = [candidate for _, candidates in scanned for candidate in candidates]

        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.info("Operation cancelled, cleaning up...")
            await self.cancellation_manager.cancel_all()
        finally:
            await connector.close()

        return all_results, all_candidates

    async def get_results(self, network_points: list[str], domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> tuple[list[ScrapNetworkUrls], set[str], list[tuple], dict[str, int]]:
        """Resources found on the pages, the page URLs requested, the redacted candidates in the page texts, and the request outcome counts."""
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        results, candidates = await self.process_network_sources(network_points=network_points, domains_input=domains_input, tld_extract=tld_extract)
        return results, self.pages, candidates, dict(self.outcomes)
