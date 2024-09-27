#!/usr/bin/env python3

import re
import asyncio
from html import unescape
import logging
import multiprocessing
from typing import List, Set
import warnings
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from bs4 import XMLParsedAsHTMLWarning
import aiohttp
import tldextract
from tenacity import retry, stop_after_attempt, retry_if_exception_type, wait_exponential
from credentialthreat.core import utils
from aiolimiter import AsyncLimiter

logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


class ScanerInternalLinks:
    def __init__(self) -> None:
        self.results: set = set()
        self.pattern_bytes_files = re.compile(r"(?=:[^\S])?(?:https?://)?[\./]*[\w/\.]+\.(?:jpg|png|gif|jpeg|bmp|webp|woff2|woff|ico|svg|mp3|mp4|mpeg|mpg|avi|zip|rar|tar|gz|pdf|ttf|exe|xml|app)", re.IGNORECASE)
        self.blacklist: Set[str] = set()
        self.sem = asyncio.Semaphore(100)
        self.rate_limiter = AsyncLimiter(100, 1)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=(
            retry_if_exception_type(aiohttp.ClientError) |
            retry_if_exception_type(asyncio.TimeoutError) |
            retry_if_exception_type(ConnectionError) |
            retry_if_exception_type(IOError) |
            retry_if_exception_type(aiohttp.client_exceptions.ServerDisconnectedError) |
            retry_if_exception_type(aiohttp.client_exceptions.ServerConnectionError) |
            retry_if_exception_type(aiohttp.client_exceptions.ClientPayloadError) |
            retry_if_exception_type(aiohttp.client_exceptions.ServerTimeoutError)
        )
    )
    async def _get_request(self, url: str, session: aiohttp.ClientSession) -> BeautifulSoup:
        async with self.sem:
            await self.rate_limiter.acquire()
            try:
                async with session.get(url, headers=utils.get_header(), allow_redirects=True, max_redirects=5) as response:
                    response_transform = await response.text('utf-8', 'ignore')
                    soup = BeautifulSoup(response_transform, 'html.parser')
                    return soup

            # NX Subdomains and SSL Subdomains Errors
            except (aiohttp.client_exceptions.ClientConnectorError, aiohttp.client_exceptions.ClientConnectorSSLError, aiohttp.ClientOSError, aiohttp.client_exceptions.InvalidURL, aiohttp.client_exceptions.ServerDisconnectedError, aiohttp.client_exceptions.ServerTimeoutError):
                self.blacklist.add(url)

            except Exception as e:
                logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {url}. Exception Message: {str(e)}")
                self.blacklist.add(url)

    async def _fetch_internal_links(self, domain: str, tld_extract: tldextract.tldextract.TLDExtract, session: aiohttp.ClientSession) -> None:
        url = 'https://' + domain
        soup = await self._get_request(url=url, session=session)

        if not soup or not soup.find_all('a'):
            return None

        for anchor in soup.find_all('a'):
            try:
                link = unescape(anchor.get("href").strip())
                if not link.startswith('javascript:'):
                    domain_name = tld_extract(link).domain
                    if len(domain_name) != 0 and domain_name in domain:
                        if self.pattern_bytes_files.search(link) is None:
                            self.results.add(link)

                    elif link.startswith('////') and len(link) > 4:
                        link_transformed = 'https://' + link[4:]
                        if self.pattern_bytes_files.search(link_transformed) is None:
                            self.results.add(link_transformed)

                    elif link.startswith('//') and len(link) > 2:
                        link_transformed = 'https://' + link[2:]
                        if self.pattern_bytes_files.search(link_transformed) is None:
                            self.results.add(link_transformed)

                    elif link.startswith('/'):
                        link_transformed = 'https://' + domain + link
                        if self.pattern_bytes_files.search(link_transformed) is None:
                            self.results.add(link_transformed)

                    elif link.startswith('./'):
                        link_transformed = 'https://' + domain + link[1:]
                        if self.pattern_bytes_files.search(link_transformed) is None:
                            self.results.add(link_transformed)

                    else:
                        link_transformed = 'https://' + domain + '/' + link
                        if self.pattern_bytes_files.search(link_transformed) is None and not link.startswith('https://') and not link.startswith('http://') and not link.startswith('#'):
                            self.results.add(link_transformed)

            except AttributeError:
                pass

    @staticmethod
    def _chunked_tasks(tasks, batch_size):
        for i in range(0, len(tasks), batch_size):
            yield tasks[i:i + batch_size]

    async def _tasks_internal_links(self, fqdns: List[str], tld_extract: tldextract.tldextract.TLDExtract, progress_queue: multiprocessing.Queue) -> None:
        connector = aiohttp.TCPConnector(ssl=False, limit_per_host=10, force_close=True,  enable_cleanup_closed=True)
        timeout = aiohttp.ClientTimeout(total=600, sock_read=30, sock_connect=30)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self._fetch_internal_links(domain=fqdn, tld_extract=tld_extract, session=session) for fqdn in fqdns]
            for task_batch in self._chunked_tasks(tasks, 100):  # Process in batches of 100
                results = await asyncio.gather(*task_batch, return_exceptions=True)
                progress_queue.put(len(task_batch))
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Error in task: {str(result)}")

    def get_results(self, iterables: list, tld_extract: tldextract.tldextract.TLDExtract, result_queue: multiprocessing.Queue, progress_queue: multiprocessing.Queue) -> None:
        logging.basicConfig(level=logging.WARNING, format='%(message)s')
        value = iterables[1]
        try:
            asyncio.run(self._tasks_internal_links(value, tld_extract, progress_queue))
        except Exception as e:
            logger.error(f"Error in get_results: {str(e)}")

        results = self.results, self.blacklist
        result_queue.put((len(value), results))
