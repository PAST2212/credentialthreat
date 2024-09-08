#!/usr/bin/env python3

import re
import asyncio
import sys
from html import unescape
import logging
import multiprocessing
from typing import List, Set, Tuple
import warnings
import socket
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from bs4 import XMLParsedAsHTMLWarning
import aiohttp
import tldextract
from tenacity import stop_after_attempt, retry_if_exception_type, wait_exponential, RetryError, AsyncRetrying
from credentialthreat.recon.wayback import ScanerWaybackMachine
from credentialthreat.core import utils

_logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


class ScanerInternalLinks:
    def __init__(self) -> None:
        self.results: set = set()
        self.pattern_bytes_files = re.compile(r"(?=:[^\S])?(?:https?://)?[\./]*[\w/\.]+\.(?:jpg|png|gif|jpeg|bmp|webp|woff2|woff|ico|svg|mp3|mp4|mpeg|mpg|avi|zip|rar|tar|gz|pdf|ttf|exe|xml|app)", re.IGNORECASE)
        self.blacklist: Set[str] = set()
        self.sem = asyncio.Semaphore(1024)

    async def _get_request(self, url: str, retries: int) -> BeautifulSoup:
        async with self.sem:
            tcp_connection = aiohttp.TCPConnector(ssl=False, family=socket.AF_INET, limit=150)
            timeout = aiohttp.ClientTimeout(total=600, sock_read=30, sock_connect=30)
            async with aiohttp.ClientSession(connector=tcp_connection, timeout=timeout) as session:
                try:
                    async for attempt in AsyncRetrying(
                            stop=stop_after_attempt(retries),
                            wait=wait_exponential(multiplier=1, min=2, max=4),
                            retry=retry_if_exception_type(
                                aiohttp.client_exceptions.ServerDisconnectedError) | retry_if_exception_type(
                                aiohttp.client_exceptions.ServerConnectionError) | retry_if_exception_type(
                                aiohttp.client_exceptions.ClientPayloadError) | retry_if_exception_type(
                                aiohttp.client_exceptions.ServerTimeoutError),
                            reraise=True,
                    ):
                        with attempt:
                            async with session.get(url, headers=utils.get_header(), allow_redirects=True, max_redirects=30) as response:
                                await asyncio.sleep(1)
                                response_transform = await response.text('utf-8', 'ignore')
                                soup = BeautifulSoup(response_transform, 'html.parser')
                                return soup

                except RetryError:
                    _logger.error(f"Failed to establish connection to {url}.")

                # NX Subdomains and SSL Subdomains Errors
                except (aiohttp.client_exceptions.ClientConnectorError, aiohttp.client_exceptions.ClientConnectorSSLError, aiohttp.ClientOSError, aiohttp.client_exceptions.InvalidURL, aiohttp.client_exceptions.ServerDisconnectedError):
                    self.blacklist.add(url)

                except asyncio.CancelledError:
                    pass

                except ConnectionResetError:
                    pass

                except Exception as e:
                    _logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {url}. Exception Message: {str(e)}")
                    self.blacklist.add(url)

    async def _fetch_internal_links(self, domain: str, tld_extract: tldextract.tldextract.TLDExtract) -> None:
        url = 'https://' + domain
        soup = await self._get_request(url=url, retries=3)

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

    async def _tasks_internal_links(self, fqdns: List[str], tld_extract: tldextract.tldextract.TLDExtract, progress_queue: multiprocessing.Queue) -> None:
        limit_workers = 100
        tasks = []
        for fqdn in fqdns:
            tasks.append(self._fetch_internal_links(domain=fqdn, tld_extract=tld_extract))

        for task_batch in self._chunked_tasks(tasks, limit_workers):
            await asyncio.gather(*task_batch)
            progress_queue.put(len(task_batch))

    @staticmethod
    def _chunked_tasks(tasks, batch_size):
        for i in range(0, len(tasks), batch_size):
            yield tasks[i:i + batch_size]

    def get_results(self, iterables: list, domains: list, tld_extract: tldextract.tldextract.TLDExtract, result_queue: multiprocessing.Queue, progress_queue: multiprocessing.Queue) -> None:
        if sys.platform == 'win32' and sys.version_info >= (3, 8):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        logging.basicConfig(level=logging.WARNING, format='%(message)s')
        value = iterables[1]

        asyncio.run(self._tasks_internal_links(value, tld_extract, progress_queue))

        results = self.results, self.blacklist

        result_queue.put((len(value), results))
