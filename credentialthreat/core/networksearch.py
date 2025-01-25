#!/usr/bin/env python3

import re
import asyncio
from urllib.parse import urljoin
from dataclasses import dataclass
import logging
import warnings
from colorama import Fore, Style
from typing import Union
import tldextract
import json
import aiohttp
from aiohttp.client_exceptions import ServerConnectionError, ServerTimeoutError, ServerDisconnectedError, ClientConnectorSSLError, InvalidURL, ClientResponseError, ClientPayloadError, ClientConnectionError, ClientOSError, ClientConnectorError, ClientProxyConnectionError
from aiolimiter import AsyncLimiter
from bs4 import BeautifulSoup, SoupStrainer
from bs4 import MarkupResemblesLocatorWarning
from bs4 import XMLParsedAsHTMLWarning
from tenacity import retry, stop_after_attempt, retry_if_exception_type, wait_exponential
from credentialthreat.core import utils

logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


@dataclass
class ScrapNetworkUrls:
    origin_url: str
    script_url: str


class ScanerNetworkResources:
    def __init__(self, max_concurrent_requests: int = 25, batch_size: int = 50) -> None:
        self.pattern_bytes_files = re.compile(
            r"(?=:\s)?(?:https?://)?[./]*[\w/.]+'\.(?:jpg|png|gif|jpeg|bmp|webp|woff2|"
            r"woff|ico|svg|mp3|mp4|mpeg|mpg|avi|zip|rar|tar|gz|pdf|ttf|exe|xml|app)",
            re.IGNORECASE
        )
        self.blacklist: set[str] = set()
        self.max_concurrent_requests = max_concurrent_requests
        self.batch_size = batch_size
        self.rate_limiter = AsyncLimiter(max_concurrent_requests, 1)
        self.strainer = SoupStrainer(['script', 'link'])

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=(
                retry_if_exception_type(ClientResponseError) |
                retry_if_exception_type(asyncio.TimeoutError) |
                retry_if_exception_type(ServerConnectionError)
        )
    )
    async def _get_request(self, url: str, header, session: aiohttp.ClientSession) -> Union[None, BeautifulSoup]:
        try:
            async with self.rate_limiter:
                async with session.get(url, headers=header, allow_redirects=True, max_redirects=5, skip_auto_headers=['Cookie'], cookie_jar=None) as response:
                    content_type = response.headers.get('content-type', '').lower()
                    text = await response.text('utf-8', 'ignore')

                    # Handle JSON responses differently; WordPress JSON API responses
                    if 'application/json' in content_type:
                        try:
                            # Parse JSON and convert to HTML for BeautifulSoup
                            json_data = json.loads(text)
                            # Create a simple HTML wrapper for JSON content
                            html_content = f"<html><body>{json.dumps(json_data)}</body></html>"
                            return BeautifulSoup(html_content, 'html.parser')
                        except json.JSONDecodeError:
                            pass

                    return BeautifulSoup(text, 'html.parser')

        except (ClientConnectionError, ClientOSError, ClientPayloadError, ClientConnectorError, ClientProxyConnectionError, InvalidURL, ClientConnectorSSLError, ServerDisconnectedError, ServerTimeoutError):
            self.blacklist.add(url)
            return None

        except Exception as e:
            logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {url}. Exception Message: {str(e)}")
            self.blacklist.add(url)
            return None

    @staticmethod
    def _clean_url(url: str) -> str:
        """ handle double-escaped URLs with backslashes """
        try:
            # Remove JSON escaping
            url = url.replace('\\"', '"').replace('\\/', '/')

            # Remove unnecessary escaping
            url = re.sub(r'\\+', '/', url)

            # Fix double slashes (except in protocol)
            url = re.sub(r'(?<!:)/{2,}', '/', url)

            # Remove any query params that look like JSON or escaped content
            url = re.sub(r'\?.*=\\.*', '', url)

            return url.strip('"\'')
        except Exception as e:
            logger.error(f"Error cleaning URL {url}: {str(e)}")
            return url

    def _extract_url(self, element: BeautifulSoup, attr: str, base_url: str, domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> list[ScrapNetworkUrls]:
        results = []
        if url := element.attrs.get(attr):
            url = self._clean_url(url)
            full_url = urljoin(base_url, url)
            if not self.pattern_bytes_files.search(full_url):
                for keyword in domains_input:
                    if tld_extract(keyword).domain in tld_extract(full_url).fqdn:
                        results.append(ScrapNetworkUrls(base_url, full_url))
        return results

    async def _fetch_network_sources(self, url: str, domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract, header, session: aiohttp.ClientSession) -> list[ScrapNetworkUrls]:
        results = []
        try:
            url = self._clean_url(url)
            if soup := await self._get_request(url, header, session):
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
                                    imported_url = urljoin(url, match.group(1))
                                    if not self.pattern_bytes_files.search(imported_url):
                                        results.append(ScrapNetworkUrls(url, imported_url))

        except:
            self.blacklist.add(url)

        return results

    async def _get_network_sources(self, network_points: list[str], domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract, header, session: aiohttp.ClientSession) -> list[ScrapNetworkUrls]:
        tasks = [self._fetch_network_sources(url, domains_input, tld_extract, header, session) for url in network_points]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for sublist in results if isinstance(sublist, list) for r in sublist]

    async def process_network_sources(self, network_points: list[str], domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> list[ScrapNetworkUrls]:
        FG, BT, FR, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Style.RESET_ALL
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit_per_host=self.max_concurrent_requests,
            force_close=False,
            keepalive_timeout=300,
            enable_cleanup_closed=True,
            ttl_dns_cache=600
        )
        timeout = aiohttp.ClientTimeout(total=45, sock_read=30, sock_connect=5)
        header = utils.get_header()

        all_results = []
        total_batches = (len(network_points) + self.batch_size - 1) // self.batch_size
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for batch_num, i in enumerate(range(0, len(network_points), self.batch_size), 1):
                batch = network_points[i:i + self.batch_size]
                try:
                    logger.info(FR + f"Starting Batch {batch_num}/{total_batches}: {len(batch)} Internal Urls" + S)
                    results = await self._get_network_sources(batch, domains_input, tld_extract, header, session)
                    all_results.extend(results)
                    logger.info(FG + f"Finished Batch {batch_num}/{total_batches}: {len(batch)} Internal Urls" + S)
                    if batch_num % 10 == 0:  # Every 10 batches (500 Subdomains/URLs with 50 batch_size)
                        pause_time = min(len(batch) / 100, 3)
                        await asyncio.sleep(pause_time)  # pause dynamically to prevent overwhelming

                except Exception as e:
                    logger.error(f"Batch {batch_num} failed: {str(e)}")
                    continue

        return all_results

    async def get_results(self, network_points: list[str], domains_input: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> tuple[list[ScrapNetworkUrls], set[str]]:
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        scraper = ScanerNetworkResources()
        results = await scraper.process_network_sources(network_points=network_points, domains_input=domains_input, tld_extract=tld_extract)
        return results, self.blacklist
