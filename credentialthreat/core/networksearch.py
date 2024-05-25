#!/usr/bin/env python3

import socket
import re
import asyncio
import sys
from urllib.parse import urljoin
import aiohttp
import logging
import warnings
import tldextract
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from bs4 import XMLParsedAsHTMLWarning
import tqdm
from tenacity import stop_after_attempt, retry_if_exception_type, wait_exponential, AsyncRetrying, RetryError
from credentialthreat.core import utils

_logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


class ScanerNetworkResources:
    def __init__(self) -> None:
        self.pattern_bytes_files = re.compile(r"(?=:[^\S])?(?:https?://)?[\./]*[\w/\.]+\.(?:jpg|png|gif|jpeg|bmp|webp|woff2|woff|ico|svg|mp3|mp4|mpeg|mpg|avi|zip|rar|tar|gz|pdf|ttf|exe|xml|app)", re.IGNORECASE)
        self.queue = asyncio.Queue()
        self.results = set()
        self.blacklist = set()

    async def _get_request(self, url: str, retries: int):
        sem = asyncio.Semaphore(1024)
        try:
            tcp_connection = aiohttp.TCPConnector(ssl=False, family=socket.AF_INET, limit=150)
            timeout = aiohttp.ClientTimeout(total=600, sock_read=30, sock_connect=30)
            async with aiohttp.ClientSession(connector=tcp_connection, timeout=timeout) as session:
                async with sem:
                    try:
                        async for attempt in AsyncRetrying(
                                stop=stop_after_attempt(retries),
                                wait=wait_exponential(multiplier=1, min=2, max=4),
                                retry=retry_if_exception_type(
                                    aiohttp.client_exceptions.ServerDisconnectedError) | retry_if_exception_type(
                                    aiohttp.client_exceptions.ServerConnectionError) | retry_if_exception_type(
                                    aiohttp.client_exceptions.ServerTimeoutError) | retry_if_exception_type(
                                    aiohttp.client_exceptions.ClientPayloadError),
                                reraise=True,
                        ):
                            with attempt:
                                async with session.get(url, headers=utils.get_header(), allow_redirects=True, max_redirects=30) as response:
                                    await asyncio.sleep(1)
                                    response_transform = await response.text('utf-8', 'ignore')
                                    soup = BeautifulSoup(response_transform, 'lxml')
                                    response.close()
                                    return soup

                    except RetryError:
                        _logger.error(f"Failed to establish connection to {url}.")

            await asyncio.sleep(0.250)

        except asyncio.CancelledError:
            pass

        except ConnectionResetError:
            pass

        except (TypeError, aiohttp.TooManyRedirects, UnicodeDecodeError):
            self.blacklist.add(url)

        # pass NXDOMAIN Domains
        except (aiohttp.ClientConnectorError, aiohttp.ClientOSError):
            self.blacklist.add(url)

        # particular happens if internal urls were not fetched correctly from source code
        except aiohttp.client_exceptions.InvalidURL as e:
            # _logger.warning(f"Warning: Unsuccessful Connection Attempt to URL {url}. Error Message: {str(e)}")
            self.blacklist.add(url)

        # Async Retry Connection Attempt Exceptions
        except (aiohttp.client_exceptions.ServerDisconnectedError, aiohttp.client_exceptions.ServerConnectionError,
                aiohttp.client_exceptions.ServerTimeoutError, aiohttp.client_exceptions.ClientPayloadError) as e:
            _logger.error(f"ConnectionRetryException. {retries} Unsuccessful Connection retries to URL {url}. Exception Message: {str(e)}")
            self.blacklist.add(url)

        except Exception as e:
            _logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {url}. Exception Message: {str(e)}")
            self.blacklist.add(url)

    async def _fetch_network_sources(self, url, domains_input):
        try:
            soup = await self._get_request(url=url, retries=3)

        except ConnectionResetError:
            return None

        if not soup:
            return None

        for script in soup.find_all("script"):
            script_item = self.extract_src(script=script, url=url, domains_input=domains_input)
            self.results.add(script_item)

        for css in soup.find_all("link"):
            src_item = self.extract_href(css=css, url=url, domains_input=domains_input)
            self.results.add(src_item)

        self.results.add((url, url))

    def extract_src(self, script, url, domains_input):
        try:
            if script.attrs.get("src"):
                script_url = urljoin(url, script.attrs.get("src"))
                if self.pattern_bytes_files.search(script_url) is None:
                    for keyword in domains_input:
                        if tldextract.extract(keyword, include_psl_private_domains=True).domain in tldextract.extract(script_url, include_psl_private_domains=True).fqdn:
                            return url, script_url

        except AttributeError:
            pass

    def extract_href(self, css, url, domains_input):
        try:
            if css.attrs.get("href"):
                css_url = urljoin(url, css.attrs.get("href"))
                if self.pattern_bytes_files.search(css_url) is None:
                    for keyword in domains_input:
                        if tldextract.extract(keyword, include_psl_private_domains=True).domain in tldextract.extract(css_url, include_psl_private_domains=True).fqdn:
                            return url, css_url

        except AttributeError:
            pass

    @staticmethod
    def _shutdown_loop():
        try:
            loop = asyncio.get_event_loop()

        except:
            loop = asyncio.new_event_loop()

        asyncio.set_event_loop(loop)

        try:
            tasks = {t for t in asyncio.all_tasks(loop=loop) if not t.done()}

            if not tasks:
                return

            for task in tasks:
                task.cancel()

            loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))

            loop.run_until_complete(asyncio.sleep(0))

            for task in tasks:
                if task.cancelled():
                    continue

            loop.run_until_complete(loop.shutdown_asyncgens())

        finally:
            loop.close()

    async def _tasks_network_sources(self, network_points: list, domains_input: list):

        limit_workers = 100

        for url in network_points:
            await self.queue.put(url)

        with tqdm.tqdm(total=len(network_points), desc='Total Progress Bar', unit='URLs') as pbar:
            while self.queue.qsize() > 0:
                try:
                    tasks = []
                    limiter = 0

                    while limiter < limit_workers and not self.queue.empty():
                        url = await self.queue.get()
                        if url is None:
                            await self.queue.put(None)
                            break

                        task = asyncio.create_task(self._fetch_network_sources(url=url, domains_input=domains_input))

                        await asyncio.sleep(0)

                        tasks.append(task)

                        limiter += 1

                    try:
                        await asyncio.gather(*tasks, return_exceptions=True)

                    except asyncio.CancelledError:
                        self._shutdown_loop()

                    # rounding errors due to limit workers batch updating
                    pbar.update(limit_workers)

                except asyncio.CancelledError:
                    pass

                except Exception as e:
                    _logger.error(f"Error: {str(type(e))}. Unknown Error occurred during Queue Management. Error Message: {str(e)}")

                finally:
                    self.queue.task_done()

    def get_results(self, iterables: list, domains_input: list, queue):
        if sys.platform == 'win32' and sys.version_info >= (3, 8):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        logging.basicConfig(level=logging.WARNING, format='%(message)s')
        value = iterables[1]
        asyncio.run(self._tasks_network_sources(value, domains_input))
        results = set(filter(lambda item: item is not None, self.results))
        results_normalized = results | self.blacklist
        queue.put((len(value), results_normalized))
