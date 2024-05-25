#!/usr/bin/env python3

import re
import asyncio
import aiohttp
import socket
import logging
import sys
from credentialthreat.core import utils
from tenacity import stop_after_attempt, retry_if_exception_type, wait_exponential, RetryError, AsyncRetrying
import tqdm

_logger = logging.getLogger(__name__)


class ScanerCredentials:
    def __init__(self) -> None:
        self.credential_pattern = r"((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]"
        self.queue = asyncio.Queue()
        self.results = []

    @staticmethod
    async def _get_request(network_files_tuple, retries):
        sem = asyncio.Semaphore(1024)
        try:
            script_url = network_files_tuple[1]
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
                                    aiohttp.client_exceptions.ServerTimeoutError) | retry_if_exception_type(aiohttp.client_exceptions.ClientPayloadError),
                                reraise=True,
                        ):
                            with attempt:
                                async with session.get(script_url, headers=utils.get_header(), allow_redirects=True, max_redirects=30) as response:
                                    await asyncio.sleep(1)
                                    response_transform = await response.text('utf-8', 'ignore')
                                    response.close()
                                    return response_transform

                    except RetryError as e:
                        _logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {network_files_tuple[1]}. Exception Message: {str(e)}")

            await asyncio.sleep(0.250)

        except asyncio.CancelledError:
            pass

        except ConnectionResetError:
            pass

        # pass NXDOMAIN Domains
        except (aiohttp.ClientConnectorError, aiohttp.ClientOSError):
            pass

        # Async Retry Connection Attempt Exceptions
        except (aiohttp.client_exceptions.ServerDisconnectedError, aiohttp.client_exceptions.ServerConnectionError,
                aiohttp.client_exceptions.ServerTimeoutError, aiohttp.client_exceptions.ClientPayloadError):
            pass

        except (TypeError, aiohttp.TooManyRedirects, UnicodeDecodeError) as e:
            _logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {network_files_tuple[1]}. Exception Message: {str(e)}")

        except Exception as e:
            _logger.error(f"Exception: {str(type(e))}. Unsuccessful Connection Attempt to URL {network_files_tuple[1]}. Exception Message: {str(e)}")

    async def _fetch_credentials(self, network_files_tuple):
        try:
            data = await self._get_request(network_files_tuple=network_files_tuple, retries=3)

        except ConnectionResetError:
            return None

        if not data:
            return None

        leaked_global = re.findall(self.credential_pattern, data, flags=re.IGNORECASE)

        if not leaked_global:
            return None

        origin_url = network_files_tuple[0]
        script_url = network_files_tuple[1]

        leaked_global_transform = [(item[-3].lower(), item[-1]) if len(item) >= 3 else (item[-2].lower(), item[-1]) for item in leaked_global]

        return origin_url, script_url, leaked_global_transform

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

    async def _tasks_credentials(self, network_files: list):

        limit_workers = 100

        results = []

        for network_files_tuple in network_files:
            await self.queue.put(network_files_tuple)

        with tqdm.tqdm(total=len(network_files), desc='Total Progress Bar', unit='URLs') as pbar:
            while self.queue.qsize() > 0:
                try:
                    tasks = []
                    limiter = 0
                    while limiter < limit_workers and not self.queue.empty():
                        network_files_tuple = await self.queue.get()
                        if network_files_tuple is None:
                            await self.queue.put(None)
                            break

                        task = asyncio.create_task(self._fetch_credentials(network_files_tuple=network_files_tuple))

                        await asyncio.sleep(0)

                        tasks.append(task)

                        limiter += 1

                    try:
                        results.extend(await asyncio.gather(*tasks, return_exceptions=True))

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

        results = list(filter(lambda item: item is not None, results))
        return results

    def get_results(self, iterables: list, queue):
        if sys.platform == 'win32' and sys.version_info >= (3, 8):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        logging.basicConfig(level=logging.WARNING, format='%(message)s')
        value = iterables[1]
        results = asyncio.run(self._tasks_credentials(value))
        queue.put((len(value), results))
