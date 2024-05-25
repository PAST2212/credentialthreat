#!/usr/bin/env python3

import re
import asyncio
from html import unescape
import tldextract
import logging
import aiohttp
import warnings
import socket
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from bs4 import XMLParsedAsHTMLWarning
from credentialthreat.recon.wayback import ScanerWaybackMachine
from credentialthreat.core import utils
from tenacity import stop_after_attempt, retry_if_exception_type, wait_exponential, RetryError, AsyncRetrying

_logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


class ScanerInternalLinks:
    def __init__(self) -> None:
        self.results: set = set()
        self.pattern_bytes_files = re.compile(r"(?=:[^\S])?(?:https?://)?[\./]*[\w/\.]+\.(?:jpg|png|gif|jpeg|bmp|webp|woff2|woff|ico|svg|mp3|mp4|mpeg|mpg|avi|zip|rar|tar|gz|pdf|ttf|exe|xml|app)", re.IGNORECASE)
        self.blacklist: set = set()

    async def _get_request(self, domain: str, retries: int):
        url = 'https://' + domain
        sem = asyncio.Semaphore(1024)
        try:
            tcp_connection = aiohttp.TCPConnector(ssl=False, family=socket.AF_INET)
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
                                    aiohttp.client_exceptions.ClientPayloadError) | retry_if_exception_type(
                                    aiohttp.client_exceptions.ServerTimeoutError) | retry_if_exception_type(
                                    aiohttp.client_exceptions.ClientPayloadError),
                                reraise=True,
                        ):
                            with attempt:
                                async with session.get(url, headers=utils.get_header(), allow_redirects=True, max_redirects=30) as response:
                                    await asyncio.sleep(1)
                                    response_transform = await response.text('utf-8', 'ignore')
                                    soup = BeautifulSoup(response_transform, 'html.parser')
                                    response.close()
                                    return soup

                    except RetryError:
                        _logger.error(f"Failed to establish connection to {url}.")

            await asyncio.sleep(0.250)

        except asyncio.CancelledError:
            pass

        except ConnectionResetError:
            pass

        # pass NXDOMAIN Domains
        except (aiohttp.ClientConnectorError, aiohttp.ClientOSError):
            self.blacklist.add(domain)

        # happens if internal urls were not fetched correctly from source code
        except aiohttp.client_exceptions.InvalidURL as e:
            self.blacklist.add(domain)
            #_logger.warning(f"Warning: Unsuccessful Connection Attempt to URL {url}. Error Message: {str(e)}")

        # Async Retry Connection Attempt Exceptions
        except (aiohttp.client_exceptions.ServerDisconnectedError, aiohttp.client_exceptions.ServerConnectionError, aiohttp.client_exceptions.ServerTimeoutError, aiohttp.client_exceptions.ClientPayloadError) as e:
            self.blacklist.add(domain)
            _logger.error(f"ConnectionRetryError. {retries} unsuccessful connection retries to URL {url}. Error Message: {str(e)}")

        except Exception as e:
            self.blacklist.add(domain)
            _logger.error(f"Error: {str(type(e))}. Unsuccessful Connection Attempt to URL {url}. Error Message: {str(e)}")

    async def _fetch_internal_links(self, domain):

        soup = await self._get_request(domain=domain, retries=3)

        if not soup:
            return None

        if not soup.find_all('a'):
            return None

        for anchor in soup.find_all('a'):
            try:
                link = unescape(anchor.get("href").strip())
                if not link.startswith('javascript:'):
                    domain_name = tldextract.extract(link, include_psl_private_domains=True).domain
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

    async def _tasks_internal_links(self, fqdns: list):

        tasks = [asyncio.create_task(self._fetch_internal_links(fqdn)) for fqdn in fqdns]

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()

    @staticmethod
    async def _get_wayback_urls(iterables: list) -> set:
        results: set = set()
        timeout = aiohttp.ClientTimeout(total=None, sock_read=30, sock_connect=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            urls = await asyncio.gather(ScanerWaybackMachine().get_results(iterables, session))
            for url in urls:
                results.update(url)

        return results

    def get_results(self, subdomains: list, domains: list) -> tuple:
        fqdns = subdomains + domains

        results_wayback = asyncio.run(self._get_wayback_urls(domains))

        results_wayback_normalized = {item for item in results_wayback if tldextract.extract(item, include_psl_private_domains=True).registered_domain in domains}
        asyncio.run(self._tasks_internal_links(fqdns))

        results_normalized = self.results | results_wayback_normalized

        return results_normalized, self.blacklist
