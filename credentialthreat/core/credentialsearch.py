#!/usr/bin/env python3

import re
import asyncio
import socket
import logging
import sys
import multiprocessing
from typing import List, Tuple
from tenacity import stop_after_attempt, retry_if_exception_type, wait_exponential, RetryError, AsyncRetrying
import aiohttp
from credentialthreat.core import utils

_logger = logging.getLogger(__name__)


class ScanerCredentials:
    def __init__(self) -> None:
        self.credential_pattern = r"((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]"
        self.results: List[Tuple[str, str, List[Tuple]]] = []
        self.sem = asyncio.Semaphore(1024)

    async def _get_request(self, url: str, retries: int) -> str:
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
                                aiohttp.client_exceptions.ServerTimeoutError) | retry_if_exception_type(
                                aiohttp.client_exceptions.ClientPayloadError),
                            reraise=True,
                    ):
                        with attempt:
                            async with session.get(url, headers=utils.get_header(), allow_redirects=True, max_redirects=30) as response:
                                await asyncio.sleep(1)
                                return await response.text('utf-8', 'ignore')

                except RetryError as e:
                    _logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {url}. Exception Message: {str(e)}")

                except asyncio.CancelledError:
                    pass

                except ConnectionResetError:
                    pass

                except (aiohttp.ClientConnectorError, aiohttp.ClientOSError):
                    pass

                except Exception as e:
                    _logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {url}. Exception Message: {str(e)}")

    async def _fetch_credentials(self, network_files_tuple: Tuple[str, str]) -> None:
        script_url = network_files_tuple[1]
        data = await self._get_request(url=script_url, retries=3)

        if not data:
            return None

        leaked_global = re.findall(self.credential_pattern, data, flags=re.IGNORECASE)

        if not leaked_global:
            return None

        origin_url = network_files_tuple[0]

        leaked_global_transform = [(item[-3].lower(), item[-1]) if len(item) >= 3 else (item[-2].lower(), item[-1]) for item in leaked_global]

        result = origin_url, script_url, leaked_global_transform

        self.results.append(result)

    async def _tasks_credentials(self, network_files: List[Tuple[str, str]], progress_queue: multiprocessing.Queue) -> None:
        limit_workers = 100
        tasks = []
        for files in network_files:
            tasks.append(self._fetch_credentials(network_files_tuple=files))

        for task_batch in self._chunked_tasks(tasks, limit_workers):
            await asyncio.gather(*task_batch)
            progress_queue.put(len(task_batch))

    @staticmethod
    def _chunked_tasks(tasks, batch_size):
        for i in range(0, len(tasks), batch_size):
            yield tasks[i:i + batch_size]

    def get_results(self, iterables: list, result_queue: multiprocessing.Queue, progress_queue: multiprocessing.Queue) -> None:
        if sys.platform == 'win32' and sys.version_info >= (3, 8):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        logging.basicConfig(level=logging.WARNING, format='%(message)s')
        value = iterables[1]

        asyncio.run(self._tasks_credentials(value, progress_queue))

        results = list(filter(lambda item: item is not None, self.results))
        result_queue.put((len(value), results))
