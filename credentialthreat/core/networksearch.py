#!/usr/bin/env python3

import re
import asyncio
from urllib.parse import urljoin
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
from credentialthreat.core.fetch import HostPacer, fetch_text, get_header
from credentialthreat.core.interrupt_handler import AsyncCancellationManager
from credentialthreat.core.website import PublicDestinationConnector, canonical_url, is_binary_url, url_in_scope


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
        self.blacklist: set[str] = set()
        self.max_concurrent_requests = max_concurrent_requests
        self.host_connections = host_connections or max_concurrent_requests  # this worker's share
        self.window_size = window_size  # requests in flight per worker process
        self.rate_limiter = AsyncLimiter(max_concurrent_requests, 1)
        self.pacer = HostPacer(rate=max_concurrent_requests, connections=self.host_connections)  # per host: pacing, 429/503 backoff, request slots
        self.cancellation_manager = AsyncCancellationManager()
        self.scope = tuple(scope)
        self.outcomes: Counter = Counter()

    async def _get_request(self, url: str, header, session: aiohttp.ClientSession) -> Union[None, tuple[str, BeautifulSoup]]:
        """Final page URL and parsed markup, or None when the page could not be read."""
        page = await fetch_text(session, url, header, scope=self.scope, limiter=self.rate_limiter,
                                pacer=self.pacer, outcomes=self.outcomes)
        if page is None:
            return None
        text = page.text
        # WordPress JSON API responses embed HTML with escaped URLs; re-serializing unescapes them.
        if 'application/json' in page.content_type:
            try:
                text = f"<html><body>{json.dumps(json.loads(text))}</body></html>"
            except json.JSONDecodeError:
                pass
        return page.url, BeautifulSoup(text, 'html.parser')

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

    @staticmethod
    def _resolve(base_url: str, reference: str, domains_input: list[str]) -> str | None:
        """Absolute, fragment-free, in-scope URL of a text resource, or None."""
        full_url = canonical_url(urljoin(base_url, reference))
        if full_url and url_in_scope(full_url, domains_input) and not is_binary_url(full_url):
            return full_url
        return None

    def _extract_url(self, element: BeautifulSoup, attr: str, base_url: str, domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> list[ScrapNetworkUrls]:
        results = []
        if url := element.attrs.get(attr):
            if full_url := self._resolve(base_url, self._clean_url(url), domains_input):
                results.append(ScrapNetworkUrls(base_url, full_url))
        return results

    async def _fetch_network_sources(self, url: str, domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract, header, session: aiohttp.ClientSession) -> list[ScrapNetworkUrls]:
        results = []
        try:
            url = canonical_url(self._clean_url(url)) or ""
            if not url_in_scope(url, domains_input):
                return results
            fetched = await self._get_request(url, header, session)
            if fetched is None:
                self.blacklist.add(url)
            else:
                url, soup = fetched
                results.append(ScrapNetworkUrls(url, url))

                for script in soup.find_all("script"):
                    results.extend(self._extract_url(script, 'src', url, domains_input, tld_extract))
                    results.extend(self._extract_url(script, 'data-src', url, domains_input, tld_extract))

                for resource in soup.find_all(['link', 'iframe', 'frame', 'embed', 'object']):
                    for attr in ['href', 'src', 'data', 'data-src']:
                        results.extend(self._extract_url(resource, attr, url, domains_input, tld_extract))

                for script in soup.find_all("script", src=None):  # inline scripts
                    if script_text := script.string:
                        # Look for dynamic imports
                        import_patterns = [
                            r'import\s+[\'"]([^\'"]+)[\'"]',
                            r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
                            r'importScripts\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
                            r'loadScript\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)'
                        ]
                        for pattern in import_patterns:
                            if matches := re.finditer(pattern, script_text):
                                for match in matches:
                                    if imported_url := self._resolve(url, match.group(1), domains_input):
                                        results.append(ScrapNetworkUrls(url, imported_url))

        except Exception:
            self.blacklist.add(url)

        return results

    async def process_network_sources(self, network_points: list[str], domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> list[ScrapNetworkUrls]:
        connector = PublicDestinationConnector(
            ssl=True,
            limit_per_host=self.host_connections,
            force_close=False,
            keepalive_timeout=300,
            enable_cleanup_closed=True,
            ttl_dns_cache=600
        )
        timeout = aiohttp.ClientTimeout(total=45, sock_read=30, sock_connect=5)
        header = get_header()

        all_results = []
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                results = await self.cancellation_manager.run_window(
                    network_points,
                    lambda url: self._fetch_network_sources(url, domains_input, tld_extract, header, session),
                    self.window_size)
                all_results = [item for found in results if isinstance(found, list) for item in found]

        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.info("Operation cancelled, cleaning up...")
            await self.cancellation_manager.cancel_all()
        finally:
            await connector.close()

        return all_results

    async def get_results(self, network_points: list[str], domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> tuple[list[ScrapNetworkUrls], set[str], dict[str, int]]:
        """Resources found on the pages, the pages that could not be read, and the request outcome counts."""
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        results = await self.process_network_sources(network_points=network_points, domains_input=domains_input, tld_extract=tld_extract)
        return results, self.blacklist, dict(self.outcomes)
