#!/usr/bin/env python3

import re
import asyncio
from urllib.parse import urljoin
import multiprocessing
import logging
import warnings
from typing import List, Set, Tuple, Union
import tldextract
import aiohttp
from aiolimiter import AsyncLimiter
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from bs4 import XMLParsedAsHTMLWarning
from tenacity import retry, stop_after_attempt, retry_if_exception_type, wait_exponential
from credentialthreat.core import utils

logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


class ScanerNetworkResources:
    def __init__(self) -> None:
        self.pattern_bytes_files = re.compile(r"(?=:[^\S])?(?:https?://)?[\./]*[\w/\.]+\.(?:jpg|png|gif|jpeg|bmp|webp|woff2|woff|ico|svg|mp3|mp4|mpeg|mpg|avi|zip|rar|tar|gz|pdf|ttf|exe|xml|app)", re.IGNORECASE)
        self.queue = asyncio.Queue()
        self.results: Set[Tuple[str, str]] = set()
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
            retry_if_exception_type(aiohttp.client_exceptions.ServerTimeoutError) |
            retry_if_exception_type(aiohttp.client_exceptions.ClientPayloadError)
        )
    )
    async def _get_request(self, url: str, session: aiohttp.ClientSession) -> BeautifulSoup:
        async with self.sem:
            await self.rate_limiter.acquire()
            try:
                async with session.get(url, headers=utils.get_header(), allow_redirects=True, max_redirects=5) as response:
                    response_transform = await response.text('utf-8', 'ignore')
                    soup = BeautifulSoup(response_transform, 'lxml')
                    return soup

            # in case for subdomains without https:// protocoll, SSL ERRORS, Malformed Fetched URLS
            except (aiohttp.client_exceptions.ClientConnectorError, aiohttp.client_exceptions.ClientConnectorSSLError,
                    aiohttp.ClientOSError, aiohttp.client_exceptions.InvalidURL,
                    aiohttp.client_exceptions.ServerDisconnectedError, aiohttp.client_exceptions.ClientPayloadError, aiohttp.client_exceptions.ServerTimeoutError):
                self.blacklist.add(url)

            except (aiohttp.ClientConnectorError, aiohttp.ClientOSError):
                pass

            except Exception as e:
                logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {url}. Exception Message: {str(e)}")
                self.blacklist.add(url)

    async def _fetch_network_sources(self, url: str, domains_input: List[str], tld_extract: tldextract.tldextract.TLDExtract, session: aiohttp.ClientSession) -> None:

        soup = await self._get_request(url=url, session=session)

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

    @staticmethod
    def _chunked_tasks(tasks, batch_size):
        for i in range(0, len(tasks), batch_size):
            yield tasks[i:i + batch_size]

    async def _tasks_network_sources(self, network_points: List[str], domains_input: List[str], tld_extract: tldextract.tldextract.TLDExtract, progress_queue: multiprocessing.Queue) -> None:
        connector = aiohttp.TCPConnector(ssl=False, limit_per_host=10, force_close=True,  enable_cleanup_closed=True)
        timeout = aiohttp.ClientTimeout(total=600, sock_read=30, sock_connect=30)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self._fetch_network_sources(url, domains_input, tld_extract, session) for url in network_points]
            for task_batch in self._chunked_tasks(tasks, 100):  # Process in batches of 100
                results = await asyncio.gather(*task_batch, return_exceptions=True)
                progress_queue.put(len(task_batch))
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Error in task: {str(result)}")

    def get_results(self, iterables: list, domains_input: list, tld_extract: tldextract.tldextract.TLDExtract, result_queue: multiprocessing.Queue, progress_queue: multiprocessing.Queue) -> None:
        logging.basicConfig(level=logging.WARNING, format='%(message)s')
        value = iterables[1]
        try:
            asyncio.run(self._tasks_network_sources(value, domains_input, tld_extract, progress_queue))
        except Exception as e:
            logger.error(f"Error in get_results: {str(e)}")

        results = set(filter(lambda item: item is not None, self.results))
        results_normalized = results | self.blacklist
        result_queue.put((len(value), results_normalized))
