#!/usr/bin/env python3

import re
import asyncio
import logging
import multiprocessing
from typing import List, Tuple
from tenacity import retry, stop_after_attempt, retry_if_exception_type, wait_exponential
import aiohttp
from aiolimiter import AsyncLimiter
from credentialthreat.core import utils

logger = logging.getLogger(__name__)


class ScanerCredentials:
    def __init__(self) -> None:
        self.credential_pattern = r"((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]"
        self.results: List[Tuple[str, str, List[Tuple]]] = []
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
    async def _get_request(self, url: str, session: aiohttp.ClientSession) -> str:
        async with self.sem:
            await self.rate_limiter.acquire()
            try:
                async with session.get(url, headers=utils.get_header(), allow_redirects=True, max_redirects=5) as response:
                    return await response.text('utf-8', 'ignore')

            except (aiohttp.ClientConnectorError, aiohttp.ClientOSError, aiohttp.client_exceptions.ClientPayloadError, aiohttp.client_exceptions.ServerTimeoutError, aiohttp.client_exceptions.ServerConnectionError, aiohttp.client_exceptions.ServerDisconnectedError):
                pass

            except Exception as e:
                logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {url}. Exception Message: {str(e)}")

    async def _fetch_credentials(self, network_files_tuple: Tuple[str, str], session: aiohttp.ClientSession) -> None:
        script_url = network_files_tuple[1]
        data = await self._get_request(url=script_url, session=session)

        if not data:
            return None

        leaked_global = re.findall(self.credential_pattern, data, flags=re.IGNORECASE)

        if not leaked_global:
            return None

        origin_url = network_files_tuple[0]

        leaked_global_transform = [(item[-3].lower(), item[-1]) if len(item) >= 3 else (item[-2].lower(), item[-1]) for item in leaked_global]

        result = origin_url, script_url, leaked_global_transform

        self.results.append(result)

    @staticmethod
    def _chunked_tasks(tasks, batch_size):
        for i in range(0, len(tasks), batch_size):
            yield tasks[i:i + batch_size]

    async def _tasks_credentials(self, network_files: List[Tuple[str, str]], progress_queue: multiprocessing.Queue) -> None:
        connector = aiohttp.TCPConnector(ssl=False, limit_per_host=10, force_close=True,  enable_cleanup_closed=True)
        timeout = aiohttp.ClientTimeout(total=600, sock_read=30, sock_connect=30)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self._fetch_credentials(network_files_tuple=files, session=session) for files in network_files]
            for task_batch in self._chunked_tasks(tasks, 100):  # Process in batches of 100
                results = await asyncio.gather(*task_batch, return_exceptions=True)
                progress_queue.put(len(task_batch))
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Error in task: {str(result)}")

    def get_results(self, iterables: list, result_queue: multiprocessing.Queue, progress_queue: multiprocessing.Queue) -> None:
        logging.basicConfig(level=logging.WARNING, format='%(message)s')
        value = iterables[1]
        try:
            asyncio.run(self._tasks_credentials(value, progress_queue))
        except Exception as e:
            logger.error(f"Error in get_results: {str(e)}")

        results = list(filter(lambda item: item is not None, self.results))
        result_queue.put((len(value), results))
