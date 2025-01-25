#!/usr/bin/env python3

import random
import re
import logging
from typing import Union
import asyncio
import multiprocessing
import psutil
import sys
from colorama import Fore, Style
import tldextract
from credentialthreat.core.credentialsearch import ScanerCredentials
from credentialthreat.core.networksearch import ScanerNetworkResources
from credentialthreat.core.networksearch import ScrapNetworkUrls


def get_workers() -> int:
    cpu_count = psutil.cpu_count(logical=False)
    print(f"{cpu_count} Physical cores detected")
    worker = cpu_count - 1
    print(f"Use {worker} CPU Cores for multiprocessing")
    return int(worker)


def get_header() -> dict:
    user_agents = [
        'Mozilla/5.0 (Linux; Android 10; LM-Q730) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 11; SM-A115F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 12; M2101K7AG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 9; INE-LX2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; CPH2179) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35',
        'Mozilla/5.0 (Linux; Android 12; motorola edge 5G UW (2021)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 9; SM-J530F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36',
        'Mozilla/5.0 (Android 10; Mobile; rv:109.0) Gecko/113.0 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.54 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.106 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; CPH1819) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 11; A509DL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 11; SM-A207M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 12; SM-M515F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; HRY-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Linux; Android 11; moto g pure) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35',
        'Mozilla/5.0 (Linux; Android 10; CPH1931) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; Infinix X656) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 11; SM-A207F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; JSN-L21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 12; SM-S127DL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Linux; Android 12; SM-A135U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.25 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Linux; Android 12; FNE-NX9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Android 11; Mobile; rv:109.0) Gecko/113.0 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36',
        'Mozilla/5.0 (Android 12; Mobile; rv:109.0) Gecko/113.0 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35',
        'Mozilla/5.0 (Linux; Android 10; SM-N960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; Lenovo TB-8505F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 12; SM-A115F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; M2004J19C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 13; SM-A536E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; ELE-L29) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; COL-L29) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.3; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/113.0 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0'
    ]

    headers = {
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': random.choice(user_agents)
    }

    return headers


# Function to configure cross-platform settings
def configure_platform_settings():
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        multiprocessing.set_start_method('spawn', force=True)
    else:
        multiprocessing.set_start_method('fork', force=True)


def deduplicate_script_urls(whitelist: list[ScrapNetworkUrls], blacklist: list[str]) -> list[tuple[str, str]]:
    """Deduplicate network URLs, keeping only unique script URLs."""
    network_files_dict = {}
    for item in whitelist:
        # Use script_url as key and origin_url as value
        network_files_dict[item.script_url] = item.origin_url

    new_network_files = [(value, key) for key, value in network_files_dict.items() if key not in blacklist]

    return list(filter(None, new_network_files))


def remove_byte_content_urls(internal_urls):
    pattern_bytes_files = re.compile(
            r"(?=:\s)?(?:https?://)?[./]*[\w/.]+'\.(?:jpg|png|gif|jpeg|bmp|webp|woff2|"
            r"woff|ico|svg|mp3|mp4|mpeg|mpg|avi|zip|rar|tar|gz|pdf|ttf|exe|xml|app)",
            re.IGNORECASE
        )
    matches_temp: set = set()

    for domain in internal_urls:
        if domain.startswith('https://') or domain.startswith('http://'):
            url = domain
        else:
            url = 'https://' + domain

        if pattern_bytes_files.search(url) is None:
            matches_temp.add(url)

    matches = list(matches_temp)
    return matches


def calculate_optimal_chunk_size(sample_urls: Union[list[str], list[tuple[str, str]]], min_size: int = 1000, max_size: int = 10000, memory_safety_factor: float = 0.5, domains_input: Union[list[str]] = None, tld_extract: Union[None, tldextract.tldextract.TLDExtract] = None) -> int:
    FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    try:
        logging.info(FY + "Calculating optimal chunk size..." + S)
        # Get initial memory usage
        initial_memory = psutil.Process().memory_info().rss

        if all(isinstance(url, tuple) for url in sample_urls):
            # Create a sample scraper and process a small batch to measure memory usage
            scraper = ScanerCredentials()

            # Run sample and measure memory
            asyncio.run(scraper.process_credentials(network_files=sample_urls))

        elif domains_input:
            # Create a sample scraper and process a small batch to measure memory usage
            scraper = ScanerNetworkResources()

            # Run sample and measure memory
            asyncio.run(scraper.process_network_sources(network_points=sample_urls, domains_input=domains_input, tld_extract=tld_extract))

        # Calculate memory used per URL
        final_memory = psutil.Process().memory_info().rss
        memory_per_url = (final_memory - initial_memory) / len(sample_urls)

        # Get available memory
        available_memory = psutil.virtual_memory().available

        # Calculate optimal size using safety factor
        safe_memory = available_memory * memory_safety_factor
        optimal_size = int(safe_memory / memory_per_url)

        # Clamp result between min and max
        chunk_size = max(min_size, min(optimal_size, max_size))

        return chunk_size

    except Exception as e:
        logging.error(f"Error calculating optimal chunk size: {e}")
        return min_size


class UrlPrioritizer:

    @staticmethod
    def _get_critical_script_url_patterns():
        # High-risk authentication and configuration patterns
        auth_patterns = [
            # Authentication and Authorization
            r'auth', r'login', r'signin', r'signup', r'register', r'oauth',
            r'sso', r'saml', r'oidc', r'jwt', r'token', r'credential',
            r'password', r'secret', r'key', r'cert',

            # Admin and Management
            r'admin', r'administrator', r'manage', r'management', r'portal',
            r'dashboard', r'console', r'control', r'supervisor', r'root',

            # Configuration and Settings
            r'config', r'conf', r'settings', r'setup', r'env', r'environment',
            r'init', r'initialize', r'install', r'configuration',

            # API and Development
            r'api', r'swagger', r'graphql', r'graphiql', r'playground',
            r'dev', r'devel', r'development', r'stage', r'staging',
            r'test', r'testing', r'beta', r'alpha', r'preprod',
            r'sandbox', r'lab', r'internal', r'private', r'restricted',

            r'security', r'auth0', r'keycloak', r'okta', r'identityserver',
            r'passport', r'credentials', r'authentication', r'authorization',
            r'permissions', r'rbac', r'acl', r'2fa', r'mfa', r'totp'

        ]

        # Development and CI/CD systems
        dev_systems = [
            # Development Tools
            r'jenkins', r'gitlab', r'github', r'bitbucket', r'azure-devops',
            r'travis', r'circle-ci', r'teamcity', r'bamboo', r'hudson',

            # Project Management
            r'jira', r'confluence', r'wiki', r'redmine', r'youtrack',
            r'trello', r'asana', r'notion', r'basecamp',

            # Source Control
            r'\.git', r'\.svn', r'\.hg', r'repository', r'repos',
            r'source', r'src', r'code', r'project',

            r'sonar', r'jenkins-ci', r'drone-ci', r'buildkite',
            r'argocd', r'spinnaker', r'tekton', r'harbor',
            r'nexus', r'artifactory', r'vault', r'secrets'
        ]

        # Backup and Legacy
        backup_patterns = [
            r'backup', r'bak', r'old', r'archive', r'archived',
            r'legacy', r'deprecated', r'previous', r'tmp', r'temp',
            r'cache', r'log', r'logs', r'dump', r'export', r'snapshot'
        ]

        # Script and Resource Extensions (Medium Priority)
        script_extensions = [
            # Client-side
            r'\.js$', r'\.jsx$', r'\.ts$', r'\.tsx$', r'\.vue$',
            r'\.json$', r'\.jsonp$', r'\.map$',

            # Server-side
            r'\.php$', r'\.asp$', r'\.aspx$', r'\.jsp$', r'\.jspx$',
            r'\.py$', r'\.rb$', r'\.env$', r'\.conf$', r'\.cfg$',
            r'\.ini$', r'\.config$', r'\.yml$', r'\.yaml$', r'\.xml$',

            # Build and Package Files
            r'package\.json$', r'composer\.json$', r'webpack\.config',
            r'\.npmrc$', r'\.yarnrc$', r'\.bowerrc$', r'Dockerfile',

            # Documentation
            r'readme', r'changelog', r'contributing', r'docs'
        ]

        # Service and Cloud Patterns
        service_patterns = [
            # Cloud Services
            r'aws', r'amazon', r'azure', r'gcp', r'googlecloud',
            r'firebase', r's3', r'lambda', r'dynamo', r'cloudfront',
            r'k8s', r'kubernetes', r'istio', r'consul',
            r'terraform', r'pulumi', r'cloudformation',
            r'eks', r'aks', r'gke', r'openshift',
            r'cluster', r'namespace', r'pod', r'deployment'

            # Common Services
            r'elasticsearch', r'kibana', r'grafana', r'prometheus',
            r'database', r'redis', r'mongo', r'mysql', r'postgres',
            r'kafka', r'rabbitmq', r'queue', r'cache', r'proxy'
        ]

        return {
            'high_priority': auth_patterns + dev_systems + service_patterns,
            'medium_priority': script_extensions + backup_patterns,
            'low_priority': []
        }

    @staticmethod
    def get_internal_url_patterns():
        internal_patterns = [
            # Internal Networks and Systems
            r'intranet', r'internal', r'internal-', r'corp', r'corporate', r'local', r'localhost',
            r'private', r'priv', r'protected', r'restricted', r'confidential',
            r'employee', r'staff', r'workplace', r'office',

            # Development Environments
            r'dev\.', r'dev-', r'development\.', r'development-',
            r'staging\.', r'stage\.', r'stage-', r'stg\.', r'stg-',
            r'test\.', r'test-', r'testing\.', r'testing-', r'tst\.', r'tst-',
            r'qa\.', r'qa-', r'qat\.', r'uat\.', r'beta\.', r'preprod\.', r'pre-prod',
            r'sandbox\.', r'sbox\.', r'integration\.', r'int\.', r'eval\.',

            # Administrative and Management
            r'admin', r'administrator', r'admins', r'adm',
            r'manage', r'management', r'manager', r'mgmt', r'administration',
            r'portal', r'dashboard', r'control', r'console', r'panel',
            r'supervisor', r'root', r'master', r'sys', r'system',

            # Authentication and Security
            r'auth\.', r'auth-', r'authentication', r'authorize', r'authorization',
            r'login\.', r'logon', r'signin', r'signup', r'register',
            r'sso\.', r'saml\.', r'oauth\.', r'oidc\.', r'keycloak\.',
            r'idp\.', r'identity', r'accounts', r'membership',
            r'password', r'passwd', r'reset', r'forgot', r'recover',
            r'security', r'secure', r'secureauth', r'trust',

            # Infrastructure and DevOps
            r'jenkins\.', r'build\.', r'ci\.', r'cd\.', r'cicd\.',
            r'gitlab\.', r'github\.', r'bitbucket\.', r'gerrit\.',
            r'artifactory\.', r'nexus\.', r'docker\.', r'registry\.',
            r'sonar\.', r'jira\.', r'confluence\.', r'wiki\.',
            r'grafana\.', r'kibana\.', r'elastic\.', r'logs?\.',
            r'monitor\.', r'metrics\.', r'stats\.', r'status\.',
            r'prometheus\.', r'alertmanager\.', r'zabbix\.',

            # Cloud and Infrastructure
            r'k8s\.', r'kubernetes\.', r'rancher\.', r'openshift\.',
            r'cluster\.', r'swarm\.', r'node\.', r'worker\.',
            r'vault\.', r'consul\.', r'etcd\.', r'config\.',
            r'aws\.', r'azure\.', r'gcp\.', r'cloud\.',

            # Service Endpoints
            r'api\.', r'api-', r'apis\.', r'service\.', r'services\.',
            r'svc\.', r'srv\.', r'app\.', r'apps\.', r'application\.',
            r'backend\.', r'frontend\.', r'web\.', r'client\.',
            r'rpc\.', r'rest\.', r'graphql\.', r'grpc\.',

            # Database and Storage
            r'db\.', r'database\.', r'sql\.', r'mysql\.', r'postgres\.',
            r'mongo\.', r'redis\.', r'cache\.', r'storage\.',
            r'backup\.', r'dump\.', r'archive\.', r'store\.',

            # Common Internal Paths
            r'/internal/', r'/admin/', r'/staff/', r'/mgmt/',
            r'/system/', r'/control/', r'/manage/', r'/dashboard/',
            r'/config/', r'/settings/', r'/setup/', r'/preferences/',
            r'/account/', r'/profile/', r'/user/', r'/users/',
            r'/auth/', r'/login/', r'/sso/', r'/saml/',
            r'/api/internal/', r'/api/v\d/internal/', r'/api/private/',
            r'/service/', r'/services/', r'/app/', r'/apps/',

            # Legacy and Backup
            r'old\.', r'backup\.', r'bak\.', r'archive\.',
            r'legacy\.', r'deprecated\.', r'obsolete\.',
            r'tmp\.', r'temp\.', r'temporary\.',

            # Organization-specific
            r'it\.', r'it-', r'helpdesk\.', r'support\.',
            r'hr\.', r'finance\.', r'accounting\.',
            r'team\.', r'group\.', r'dept\.', r'department\.',
            r'project\.', r'projects\.', r'tasks\.',

            # Additional Infrastructure
            r'middleware\.', r'gateway\.', r'proxy\.', r'loadbalancer\.',
            r'lb\.', r'cdn\.', r'edge\.', r'router\.',
            r'vpn\.', r'tunnel\.', r'remote\.', r'access\.',

            # Modern Authentication
            r'mfa\.', r'2fa\.', r'totp\.', r'webauthn\.',
            r'authenticator\.', r'verify\.', r'verification\.',
            r'/oauth2/', r'/oidc/', r'/connect/token/',

            # Development Tools
            r'deploy\.', r'deployment\.', r'release\.',
            r'feature\.', r'hotfix\.', r'bugfix\.',
            r'release-', r'feature-', r'hotfix-',

            # Content Management
            r'cms\.', r'content\.', r'assets\.',
            r'media\.', r'static\.', r'resources\.',
            r'/cms/', r'/content/', r'/assets/',

            # Analytics and Monitoring
            r'analytics\.', r'tracking\.', r'telemetry\.',
            r'logging\.', r'logger\.', r'audit\.',
            r'/analytics/', r'/metrics/', r'/monitoring/',

            # Payment and Transaction
            r'payment\.', r'transaction\.', r'checkout\.',
            r'billing\.', r'invoice\.', r'order\.',
            r'/payment/', r'/transaction/', r'/billing/',

            # Common Web Services
            r'ws\.', r'websocket\.', r'socket\.',
            r'event\.', r'stream\.', r'push\.',
            r'/ws/', r'/events/', r'/stream/',

            # Common URL Structures
            r'-internal\.', r'-private\.', r'-sys\.',
            r'-backend\.', r'-admin\.', r'-mgmt\.',
            r'/v1/internal/', r'/v2/internal/', r'/v3/internal/',
            r'/private/v1/', r'/private/v2/', r'/private/v3/'
        ]

        return {'internal_pattern': internal_patterns}

    def prioritize_urls(self, urls: Union[list[tuple[str, str]], list[str]], limit: int) -> Union[list[tuple[str, str]], list[str]]:
        """Prioritize network and internal URLs based on likelihood of credential exposure."""

        FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL

        if not urls:
            return []

        script_patterns = self._get_critical_script_url_patterns()
        internal_patterns = self.get_internal_url_patterns()['internal_pattern']

        is_internal = isinstance(urls[0], str)
        url_type = "Internal" if is_internal else "Network"

        seen_urls = set()
        high_priority = []
        medium_priority = []
        low_priority = []

        if is_internal:
            for url in urls:
                if not isinstance(url, str):
                    continue

                if url in seen_urls:
                    continue
                seen_urls.add(url)
                url_lower = url.lower()
                if any(pattern in url_lower for pattern in internal_patterns):
                    high_priority.append(url)
                else:
                    low_priority.append(url)

        else:
            for url_obj in urls:
                origin_url, script_url = url_obj
                if script_url in seen_urls:
                    continue
                seen_urls.add(script_url)
                script_url_lower = script_url.lower()
                if any(pattern in script_url_lower for pattern in script_patterns['high_priority']):
                    high_priority.append(url_obj)
                elif any(pattern in script_url_lower for pattern in script_patterns['medium_priority']):
                    medium_priority.append(url_obj)
                else:
                    low_priority.append(url_obj)

        total_urls = len(urls)
        high_count = len(high_priority)
        med_count = len(medium_priority)
        low_count = len(low_priority)

        logging.info(FY + f"\n{url_type} URL Analysis:"
                          f"\n├── Total URLs Found: {total_urls:,}"
                          f"\n├── Priority Distribution:"
                          f"\n│   ├── High Priority: {high_count:,} ({high_count / total_urls * 100:.1f}%)"
                          f"\n│   {'├── Medium Priority: ' + str(med_count) + f' ({med_count / total_urls * 100:.1f}%)' if not is_internal else '│'}"
                          f"\n│   └── Low Priority: {low_count:,} ({low_count / total_urls * 100:.1f}%)"
                          f"\n└── URL Limit: {limit:,}" + S)

        if high_count >= limit:
            result = high_priority[:limit]
            logging.info(FY + f"\nFinal Selection:"
                              f"\n└── Using {limit:,} high priority URLs only (limit reached)" + S)
        else:
            result = high_priority
            remaining = limit - high_count

            if not is_internal and remaining > 0 and medium_priority:
                med_used = min(remaining, med_count)
                result.extend(medium_priority[:med_used])
                remaining -= med_used

            if remaining > 0 and low_priority:
                low_used = min(remaining, low_count)
                result.extend(low_priority[:low_used])

            # Log final distribution
            final_high = len(high_priority)
            final_med = len(medium_priority[:limit - high_count]) if not is_internal else 0
            final_low = min(limit - len(result) + final_med, low_count)

            logging.info(FY + f"\nFinal Selection:"
                              f"\n├── Selected URLs: {len(result):,}"
                              f"\n├── Distribution:"
                              f"\n│   ├── High Priority: {final_high:,} ({final_high / len(result) * 100:.1f}%)"
                              f"\n│   {'├── Medium Priority: ' + str(final_med) + f' ({final_med / len(result) * 100:.1f}%)' if not is_internal else '│'}"
                              f"\n│   └── Low Priority: {final_low:,} ({final_low / len(result) * 100:.1f}%)"
                              f"\n└── Limit: {limit:,}\n" + S)

        return result[:limit]
