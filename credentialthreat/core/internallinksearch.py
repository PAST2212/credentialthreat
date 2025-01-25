#!/usr/bin/env python3

import re
import asyncio
from html import unescape
import logging
from typing import Union
import warnings
from colorama import Fore, Style
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from bs4 import XMLParsedAsHTMLWarning
import aiohttp
from aiohttp.client_exceptions import ServerConnectionError, ClientResponseError
import tldextract
from tenacity import retry, stop_after_attempt, retry_if_exception_type, wait_exponential
from credentialthreat.core import utils
from aiolimiter import AsyncLimiter

logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


class ScanerInternalLinks:
    def __init__(self, max_concurrent_requests: int = 25, batch_size: int = 50) -> None:
        self.pattern_bytes_files = re.compile(
            r"(?=:\s)?(?:https?://)?[./]*[\w/.]+'\.(?:jpg|png|gif|jpeg|bmp|webp|woff2|"
            r"woff|ico|svg|mp3|mp4|mpeg|mpg|avi|zip|rar|tar|gz|pdf|ttf|exe|xml|app)",
            re.IGNORECASE
        )
        self.max_concurrent_requests = max_concurrent_requests
        self.batch_size = batch_size
        self.rate_limiter = AsyncLimiter(max_concurrent_requests, 1)
        self.blacklist: set[str] = set()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=(
                retry_if_exception_type(ClientResponseError) |
                retry_if_exception_type(asyncio.TimeoutError) |
                retry_if_exception_type(ServerConnectionError)
        )
    )
    async def _get_request(self, url: str, header: dict, session: aiohttp.ClientSession) -> Union[BeautifulSoup, None]:
        try:
            async with self.rate_limiter:
                async with session.get(url, headers=header, allow_redirects=True, max_redirects=5) as response:
                    html = await response.text('utf-8', 'ignore')
                    soup = BeautifulSoup(html, 'html.parser')
                    return soup

        # NX Subdomains and SSL Subdomains Errors
        except (aiohttp.client_exceptions.ClientConnectorError, aiohttp.client_exceptions.ClientConnectorSSLError, aiohttp.ClientOSError, aiohttp.client_exceptions.InvalidURL, aiohttp.client_exceptions.ServerDisconnectedError, aiohttp.client_exceptions.ServerTimeoutError):
            self.blacklist.add(url)
            return None

        except Exception as e:
            logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {url}. Exception Message: {str(e)}")
            self.blacklist.add(url)
            return None

    def _process_link(self, link: str, domain: str, tld_extract: tldextract.tldextract.TLDExtract) -> Union[str, None]:
        try:
            link = unescape(link.strip())
            if link.startswith('javascript:'):
                return None

            domain_name = tld_extract(link).domain
            if len(domain_name) != 0 and domain_name in domain:
                if self.pattern_bytes_files.search(link) is None:
                    return link

            if link.startswith('////') and len(link) > 4:
                link_transformed = 'https://' + link[4:]
            elif link.startswith('//') and len(link) > 2:
                link_transformed = 'https://' + link[2:]
            elif link.startswith('/'):
                link_transformed = 'https://' + domain + link
            elif link.startswith('./'):
                link_transformed = 'https://' + domain + link[1:]
            else:
                if not any(link.startswith(prefix) for prefix in ('https://', 'http://', '#')):
                    link_transformed = 'https://' + domain + '/' + link
                else:
                    return None

            if self.pattern_bytes_files.search(link_transformed) is None:
                return link_transformed

        except (AttributeError, ValueError):
            pass

        return None

    async def _fetch_internal_links(self, domain: str, tld_extract: tldextract.tldextract.TLDExtract, header: dict, session: aiohttp.ClientSession):
        results: set = set()
        url = 'https://' + domain
        try:
            if soup := await self._get_request(url, header, session):
                results.add(url)
                for anchor in soup.find_all('a'):
                    href = anchor.get("href")
                    if href:
                        if processed_link := self._process_link(href, domain, tld_extract):
                            results.add(processed_link)
        except Exception as e:
            logger.error(f"Error processing {url}: {str(e)}")
            self.blacklist.add(url)

        return results

    async def _get_internal_links(self, urls: list[str], tld_extract: tldextract.tldextract.TLDExtract, header: dict, session: aiohttp.ClientSession):
        tasks = [self._fetch_internal_links(fqdn, tld_extract, header, session) for fqdn in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for sublist in results if isinstance(sublist, set) for r in sublist]

    async def process_internal_links(self, fqdns: list[str], tld_extract: tldextract.tldextract.TLDExtract):
        FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL
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

        all_results: set = set()
        total_batches = (len(fqdns) + self.batch_size - 1) // self.batch_size
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                for batch_num, i in enumerate(range(0, len(fqdns), self.batch_size), 1):
                    batch = fqdns[i:i + self.batch_size]
                    try:
                        logger.info(FR + f"Starting Batch {batch_num}/{total_batches}: {len(batch)} Full Qualified Domain Names" + S)
                        results = await self._get_internal_links(batch, tld_extract, header, session)
                        all_results.update(results)
                        logger.info(FG + f"Finished Batch {batch_num}/{total_batches}: {len(batch)} Full Qualified Domain Names" + S)
                        if batch_num % 10 == 0:  # Every 10 batches (500 Subdomains/URLs with 50 batch_size)
                            pause_time = min(len(batch) / 100, 3)
                            await asyncio.sleep(pause_time)  # pause dynamically to prevent overwhelming

                    except Exception as e:
                        logger.error(f"Batch {batch_num} failed: {str(e)}")
                        continue

        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.info("\nOperation cancelled, cleaning up...")

        return all_results

    async def get_results(self, fqdns: list[str], tld_extract: tldextract.tldextract.TLDExtract) -> tuple[set[str], set[str]]:
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        scraper = ScanerInternalLinks()
        results = await scraper.process_internal_links(fqdns=fqdns, tld_extract=tld_extract)
        return results, self.blacklist
