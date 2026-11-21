#!/usr/bin/env python3

import re
import asyncio
import logging
from typing import Union
from collections import Counter
from urllib.parse import urlsplit
import aiohttp
from aiolimiter import AsyncLimiter
from credentialthreat.core.fetch import HostPacer, Page, fetch_text, get_header
from credentialthreat.core.interrupt_handler import AsyncCancellationManager
from credentialthreat.core.website import PublicDestinationConnector, module_imports, report_origin, resolve_reference


logger = logging.getLogger(__name__)

# Case-insensitive matching folds A-Z and these four letters onto ASCII lower case (dotted and dotless i, long s, Kelvin sign).
# Each maps to exactly one character, so a folded copy keeps every span of the original text.
CASE_FOLD = str.maketrans({**{chr(code): chr(code + 32) for code in range(ord("A"), ord("Z") + 1)},
                           "\u0130": "i", "\u0131": "i", "\u017f": "s", "\u212a": "k"})


class ScanerCredentials:
    def __init__(self, max_concurrent_requests: int = 25, window_size: int = 50, scope=(),
                 host_connections: int | None = None) -> None:
        # Base credential pattern (your existing patterns)
        base_pattern = (
            # "h4x0r-dz" patterns
            r"access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|"
            r"alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|"
            r"aos_key|api_key|api_key_secret|api_key_sid|api_secret|api\.googlemaps AIza|apidocs|"
            r"apikey|apiSecret|app_id|app_key|app_secret|appkey|appkeysecret|"
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

        assignment = (
            # Rest of the key name and separators. No comma: it would run into the next property's value.
            r")[a-z0-9_ .\-]{0,25}" +
            r"(?:=|>|:=|\|\|:|<=|=>|:|->|\+=|\-=|\*=|\/=|%=|\^=|&=|\|=|==|\+=|<<=|>>=|=>|\?=|\?\?=)" +  # Operators
            r"\s*" +  # Optional whitespace
            r"(?P<quote>['\"])" +
            r"(?!same-origin(?P=quote))" +  # Fetch API option credentials: "same-origin", not a secret
            r"(?P<value>[0-9a-zA-Z\-_=+/]{8,128})(?P=quote)"
        )
        # The rule as written, matched case-insensitively (tests/measure_rules.py reads it).
        self.credential_pattern = r"(?P<label>" + base_pattern + assignment
        # The same rule for _findings: lower-case field names, matched against a CASE_FOLD copy of the text.
        # With IGNORECASE, re tries every field name at every position (about 1.5 s per MB of script, which
        # blocks the worker's event loop); case-sensitive, it skips positions by their first letter.
        self._assignment = re.compile(r"(?P<label>" + base_pattern.lower() + assignment, re.MULTILINE)

        # Add additional specific patterns for special cases
        self.additional_patterns = {
            'jwt': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'private_key': (r'-----BEGIN (?P<kind>(?:RSA )?PRIVATE KEY)-----'
                            r'[A-Za-z0-9\s/+=]+-----END (?P=kind)-----'),
            'aws_keys': r'AKIA[0-9A-Z]{16}'
        }

        self.max_concurrent_requests = max_concurrent_requests
        self.host_connections = host_connections or max_concurrent_requests  # this worker's share
        self.window_size = window_size  # requests in flight per worker process
        self.rate_limiter = AsyncLimiter(max_concurrent_requests, 1)
        self.pacer = HostPacer(rate=max_concurrent_requests, connections=self.host_connections)  # per host: pacing, 429/503 backoff, request slots
        self.cancellation_manager = AsyncCancellationManager()
        self.scope = tuple(scope)
        self.outcomes: Counter = Counter()
        self.imports: set[tuple[str, str]] = set()  # (origin page, module URL) imported by the scripts read here

    def _collect_imports(self, origin_url: str, page: Page) -> None:
        """Remember the in-scope modules a script that loaded imports; the CLI fetches them in a later round."""
        content_type = page.content_type
        is_script = "javascript" in content_type or "ecmascript" in content_type or (
            not content_type and urlsplit(page.url).path.endswith((".js", ".mjs")))
        if not is_script or not 200 <= page.status < 300:
            return
        for specifier in module_imports(page.text):
            if url := resolve_reference(page.url, specifier, self.scope):
                self.imports.add((origin_url, url))

    def _findings(self, data: str) -> list[tuple[str, str]]:
        labels_by_span: dict[tuple[int, int], list[str]] = {}
        for match in self._assignment.finditer(data.translate(CASE_FOLD)):
            labels_by_span[match.span("value")] = [data[slice(*match.span("label"))].lower()]
        for pattern_name, pattern in self.additional_patterns.items():
            for match in re.finditer(pattern, data):
                labels = labels_by_span.setdefault(match.span(), [])
                if pattern_name not in labels:
                    labels.append(pattern_name)
        return [(" + ".join(labels), "[REDACTED]") for labels in labels_by_span.values()]

    async def _get_request(self, url_tuple: tuple[str, str], header, session: aiohttp.ClientSession) -> Union[None, tuple[str, str, list[tuple]]]:
        origin_url, script_url = url_tuple
        # Matching another resource can block this worker's loop past sock_connect and turn a connection that
        # succeeded into a connect timeout, so retry once (a dead host costs one more connect timeout).
        page = await fetch_text(session, script_url, header, scope=self.scope, limiter=self.rate_limiter,
                                pacer=self.pacer, outcomes=self.outcomes, connect_retries=1)
        if page is None or not page.text:
            return None
        self._collect_imports(origin_url, page)
        if findings := self._findings(page.text):
            return report_origin(origin_url), report_origin(page.url), findings
        return None

    async def process_credentials(self, network_files: list[tuple[str, str]]):
        connector = PublicDestinationConnector(
            limit_per_host=self.host_connections,
            force_close=False,
            keepalive_timeout=300,
            enable_cleanup_closed=True,
            ttl_dns_cache=600
        )
        timeout = aiohttp.ClientTimeout(total=45, sock_read=30, sock_connect=5)
        header = get_header()

        all_results = []
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                results = await self.cancellation_manager.run_window(
                    network_files, lambda url_tuple: self._get_request(url_tuple, header, session), self.window_size)
                all_results = [result for result in results if isinstance(result, tuple)]

        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.info("Operation cancelled, cleaning up...")
            await self.cancellation_manager.cancel_all()
        finally:
            await connector.close()

        return all_results

    async def get_results(self, network_files: list[tuple[str, str]]) -> tuple[list[tuple], dict[str, int], list[tuple[str, str]]]:
        """Redacted candidates per resource, the request outcome counts, and the modules the scripts import."""
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        results = await self.process_credentials(network_files=network_files)
        return results, dict(self.outcomes), sorted(self.imports)
