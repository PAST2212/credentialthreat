#!/usr/bin/env python3

import re
import asyncio
import logging
from typing import Union
from colorama import Fore, Style
from tenacity import retry, stop_after_attempt, retry_if_exception_type, wait_exponential
import aiohttp
from aiohttp.client_exceptions import ServerConnectionError, ClientResponseError, ClientPayloadError, ClientConnectionError, ClientOSError, ClientConnectorError, ClientProxyConnectionError
from aiolimiter import AsyncLimiter
from credentialthreat.core import utils


logger = logging.getLogger(__name__)


class ScanerCredentials:
    def __init__(self, max_concurrent_requests: int = 25, batch_size: int = 50) -> None:
        # Base credential pattern (your existing patterns)
        base_pattern = (
            # "h4x0r-dz" patterns
            r"access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|"
            r"alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|"
            r"aos_key|api_key|api_key_secret|api_key_sid|api_secret|api\.googlemaps AIza|apidocs|"
            r"apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|"
            r"application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|"
            r"aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|"
            r"b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|"
            r"bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|"
            r"bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|"
            r"cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|"
            r"client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|"
            r"cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|"
            r"codecov_token|conn\.login|connectionstring|consumer_key|consumer_secret|credentials|"
            r"cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|"
            r"db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|"
            r"digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|"
            r"docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|"
            r"droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|"
            r"elasticsearch_password|encryption_key|encryption_password|env\.heroku_api_key|"
            r"env\.sonatype_password|eureka\.awssecretkey|"

            # Modern service keys
            r"firebase_api_key|stripe_secret_key|stripe_publishable_key|twilio_account_sid|"
            r"twilio_auth_token|github_token|github_secret|gitlab_token|okta_client_secret|"
            r"okta_api_token|sendgrid_api_key|mailgun_api_key|mailchimp_api_key|"

            # OAuth and JWT patterns
            r"oauth_token|oauth_secret|refresh_token|id_token|jwt_secret|jwt_token|session_secret|"

            # Cloud platform specific
            r"azure_tenant|azure_subscription|gcp_credentials|gcp_service_account|"
            r"aws_session_token|do_auth_token|cf_api_key|"

            # Database connection strings
            r"mongodb_uri|postgres_url|mysql_url|redis_url|cassandra_auth|elasticsearch_url|"

            # Development and CI/CD
            r"npm_token|nuget_api_key|rubygems_auth|pypi_token|docker_auth|artifactory_api_key|"
            r"jenkins_api_token|circle_token|travis_token|sonar_token|"

            # Security tools and monitoring
            r"kubernetes_secret|k8s_token|vault_token|consul_token|"
            r"keycloak_secret|oauth_client_secret|saml_key|ldap_bind|"
            r"snyk_token|checkmarx_key|fortify_token|"
            r"splunk_token|elk_api_key|sumologic_key|"

            # Private keys and certificates
            r"private_key|public_key|ssl_key|ssh_key|gpg_key|certificate"
        )

        # Construct the full pattern
        self.credential_pattern = (
            r"((" + base_pattern + r")[a-z0-9_ .\-,]{0,25})" +  # Key names and separators
            r"(=|>|:=|\|\|:|<=|=>|:|->|\+=|\-=|\*=|\/=|%=|\^=|&=|\|=|==|\+=|<<=|>>=|=>|\?=|\?\?=)" +  # Operators
            r"\s*" +  # Optional whitespace
            r"['\"]([0-9a-zA-Z\-_=+/]{8,128})['\"]"  # Value pattern
        )

        # Add additional specific patterns for special cases
        self.additional_patterns = {
            'jwt': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'private_key': r'-----BEGIN (?:RSA )?PRIVATE KEY-----[A-Za-z0-9\s/+=]+-----END (?:RSA )?PRIVATE KEY-----',
            'aws_keys': r'AKIA[0-9A-Z]{16}'
        }

        self.max_concurrent_requests = max_concurrent_requests
        self.batch_size = batch_size
        self.rate_limiter = AsyncLimiter(max_concurrent_requests, 1)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=(
            retry_if_exception_type(ClientResponseError) |
            retry_if_exception_type(asyncio.TimeoutError) |
            retry_if_exception_type(ServerConnectionError) |
            retry_if_exception_type(ClientPayloadError)
        )
    )
    async def _get_request(self, url_tuple: tuple[str, str], header, session: aiohttp.ClientSession) -> Union[None, tuple[str, str, list[tuple]]]:
        origin_url, script_url = url_tuple
        try:
            async with self.rate_limiter:
                async with session.get(script_url, headers=header, allow_redirects=True, max_redirects=5) as response:
                    data = await response.text('utf-8', 'ignore')

                    if not data:
                        return None

                    leaked_global = re.findall(self.credential_pattern, data, flags=re.IGNORECASE | re.MULTILINE)

                    for pattern_name, pattern in self.additional_patterns.items():
                        additional_matches = re.findall(pattern, data)
                        for match in additional_matches:
                            leaked_global.append((pattern_name, match))

                    if not leaked_global:
                        return None

                    leaked_global = [(item[-3].lower(), item[-1]) if len(item) >= 3 else (item[-2].lower(), item[-1]) for item in leaked_global]

                    return origin_url, script_url, leaked_global

        except (ClientResponseError, asyncio.TimeoutError, ServerConnectionError, ClientPayloadError):
            raise

        except (ClientConnectionError, ClientOSError, ClientConnectorError, ClientProxyConnectionError):
            return None

        except Exception as e:
            logger.error(f"Unexpected error for {script_url}: {str(e)}")
            return None

    async def _fetch_credentials(self, network_files_batch: list[tuple[str, str]], header, session: aiohttp.ClientSession):
        tasks = [self._get_request(url_tuple, header, session) for url_tuple in network_files_batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, tuple)]

    async def process_credentials(self, network_files: list[tuple[str, str]]):
        FG, BT, FR, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Style.RESET_ALL
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

        all_results = []
        total_batches = (len(network_files) + self.batch_size - 1) // self.batch_size

        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                for batch_num, i in enumerate(range(0, len(network_files), self.batch_size), 1):
                    batch = network_files[i:i + self.batch_size]
                    try:
                        logger.info(FR + f"Starting Batch {batch_num}/{total_batches}: {len(batch)} Network Urls" + S)
                        results = await self._fetch_credentials(batch, header, session)
                        all_results.extend(results)
                        logger.info(FR + f"Finished Batch {batch_num}/{total_batches}: {len(batch)} Network Urls" + S)
                        if batch_num % 10 == 0:  # Every 10 batches (500 Subdomains with 50 batch_size)
                            pause_time = min(len(batch) / 100, 3)
                            await asyncio.sleep(pause_time)  # pause dynamically to prevent overwhelming

                    except Exception as e:
                        logger.error(f"Batch {batch_num} failed: {str(e)}")
                        continue

        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.info("\nOperation cancelled, cleaning up...")

        return all_results

    @staticmethod
    async def get_results(network_files: list[tuple[str, str]]) -> list[tuple]:
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        scraper = ScanerCredentials()
        results = await scraper.process_credentials(network_files=network_files)
        return results
