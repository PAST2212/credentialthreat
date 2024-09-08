#!/usr/bin/env python3

import socket
import re
import asyncio
import sys
from urllib.parse import urljoin
import multiprocessing
import logging
import warnings
from typing import List, Set, Tuple, Union
import tldextract
import aiohttp
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from bs4 import XMLParsedAsHTMLWarning
from tenacity import stop_after_attempt, retry_if_exception_type, wait_exponential, AsyncRetrying, RetryError
from credentialthreat.core import utils


_logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


class ScanerNetworkResources:
    def __init__(self) -> None:
        self.pattern_bytes_files = re.compile(r"(?=:[^\S])?(?:https?://)?[\./]*[\w/\.]+\.(?:jpg|png|gif|jpeg|bmp|webp|woff2|woff|ico|svg|mp3|mp4|mpeg|mpg|avi|zip|rar|tar|gz|pdf|ttf|exe|xml|app)", re.IGNORECASE)
        self.queue = asyncio.Queue()
        self.results: Set[Tuple[str, str]] = set()
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
                                (aiohttp.client_exceptions.ServerDisconnectedError,
                                 aiohttp.client_exceptions.ServerConnectionError,
                                 aiohttp.client_exceptions.ClientPayloadError,
                                 aiohttp.client_exceptions.ServerTimeoutError)
                            ),
                            reraise=True,
                    ):
                        with attempt:
                            async with session.get(url, headers=utils.get_header(), allow_redirects=True, max_redirects=30) as response:
                                await asyncio.sleep(1)
                                response_transform = await response.text('utf-8', 'ignore')
                                soup = BeautifulSoup(response_transform, 'lxml')
                                return soup

                except RetryError:
                    _logger.error(f"Failed to establish connection to {url}.")

                # in case for subdomains without https:// protocoll, SSL ERRORS, Malformed Fetched URLS
                except (aiohttp.client_exceptions.ClientConnectorError, aiohttp.client_exceptions.ClientConnectorSSLError, aiohttp.ClientOSError, aiohttp.client_exceptions.InvalidURL, aiohttp.client_exceptions.ServerDisconnectedError):
                    self.blacklist.add(url)

                except asyncio.CancelledError:
                    pass

                except ConnectionResetError:
                    pass

                except Exception as e:
                    _logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {url}. Exception Message: {str(e)}")
                    self.blacklist.add(url)

    async def _fetch_network_sources(self, url: str, domains_input: List[str], tld_extract: tldextract.tldextract.TLDExtract) -> None:

        soup = await self._get_request(url=url, retries=3)

        if not soup:
            return None

        for script in soup.find_all("script"):
            script_item = self.extract_src(script=script, url=url, domains_input=domains_input, tld_extract=tld_extract)
            if script_item:
                self.results.add(script_item)

        for css in soup.find_all("link"):
            src_item = self.extract_href(css=css, url=url, domains_input=domains_input, tld_extract=tld_extract)
            if src_item:
                self.results.add(src_item)

        self.results.add((url, url))

    def extract_src(self, script, url: str, domains_input: List[str], tld_extract: tldextract.tldextract.TLDExtract) -> Union[Tuple[str, str], None]:
        if script.attrs.get("src"):
            script_url = urljoin(url, script.attrs.get("src"))
            if self.pattern_bytes_files.search(script_url) is None:
                for keyword in domains_input:
                    if tld_extract(keyword).domain in tld_extract(script_url).fqdn:
                        return url, script_url

        return None

    def extract_href(self, css, url: str, domains_input: List[str], tld_extract: tldextract.tldextract.TLDExtract) -> Union[Tuple[str, str], None]:
        if css.attrs.get("href"):
            css_url = urljoin(url, css.attrs.get("href"))
            if self.pattern_bytes_files.search(css_url) is None:
                for keyword in domains_input:
                    if tld_extract(keyword).domain in tld_extract(css_url).fqdn:
                        return url, css_url

        return None

    async def _tasks_network_sources(self, network_points: List[str], domains_input: List[str], tld_extract: tldextract.tldextract.TLDExtract, progress_queue: multiprocessing.Queue) -> None:
        limit_workers = 100
        tasks = []
        for url in network_points:
            tasks.append(self._fetch_network_sources(url=url, domains_input=domains_input, tld_extract=tld_extract))

        for task_batch in self._chunked_tasks(tasks, limit_workers):
            await asyncio.gather(*task_batch)
            progress_queue.put(len(task_batch))

    @staticmethod
    def _chunked_tasks(tasks, batch_size):
        for i in range(0, len(tasks), batch_size):
            yield tasks[i:i + batch_size]

    def get_results(self, iterables: list, domains_input: list, tld_extract: tldextract.tldextract.TLDExtract, result_queue: multiprocessing.Queue, progress_queue: multiprocessing.Queue) -> None:
        if sys.platform == 'win32' and sys.version_info >= (3, 8):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        logging.basicConfig(level=logging.WARNING, format='%(message)s')
        value = iterables[1]

        asyncio.run(self._tasks_network_sources(value, domains_input, tld_extract, progress_queue))

        results = set(filter(lambda item: item is not None, self.results))
        results_normalized = results | self.blacklist
        result_queue.put((len(value), results_normalized))
