#!/usr/bin/env python3

import re
import logging
from collections import deque
from urllib.parse import urlsplit
from typing import Union
import asyncio
import multiprocessing
import psutil
import sys
from colorama import Fore, Style
from credentialthreat.core.networksearch import ScrapNetworkUrls
from credentialthreat.core.fetch import get_header  # noqa: F401  (used by recon modules)


def get_workers() -> int:
    cpu_count = psutil.cpu_count(logical=False)
    print(f"{cpu_count} Physical cores detected")
    worker = cpu_count - 1
    print(f"Use {worker} CPU Cores for multiprocessing")
    return int(worker)


# Function to configure cross-platform settings
def configure_platform_settings():
    if sys.platform.startswith('win'):
        # The native proactor wakes its I/O wait when the main thread receives a signal.
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        multiprocessing.set_start_method('spawn', force=True)
    else:
        multiprocessing.set_start_method('fork', force=True)


def deduplicate_script_urls(whitelist: list[ScrapNetworkUrls], blacklist: set[str]) -> list[tuple[str, str]]:
    """Deduplicate network URLs, keeping only unique script URLs that are not in the blacklist."""
    network_files_dict = {}
    for item in whitelist:
        # Use script_url as key and origin_url as value
        network_files_dict[item.script_url] = item.origin_url

    new_network_files = [(value, key) for key, value in network_files_dict.items() if key not in blacklist]

    return list(filter(None, new_network_files))


HOST_CONNECTIONS = 25  # parallel connections one host may see from the whole scan


def host_connections_per_worker(workers: int) -> int:
    """Each worker's share of the per-host connection budget.

    Every worker works on every host at the same time, so without a shared budget the load on a
    host would grow with the number of CPU cores.
    """
    return max(2, HOST_CONNECTIONS // max(1, workers))


def plan_chunks(items: list, workers: int) -> list[list]:
    """Deal items round-robin into one chunk per worker (fewer when there are fewer items).

    A chunk only finishes with its slowest request, so each additional chunk per worker would add
    a stretch with few requests in flight. Dealing instead of slicing mixes the hosts of a sorted
    list into every chunk, which keeps the chunks similar in duration. Within a chunk the hosts take
    turns, so one host with many items does not hold the others back.
    Peak memory depends on the requests in flight per worker, not on the chunk size.
    """
    items = list(items)
    count = min(len(items), max(1, workers))
    return [interleave_by_host(items[index::count]) for index in range(count)]


def _request_host(item) -> str:
    """The host an item is requested from: a host name, a URL, or the resource URL of an (origin, resource) pair."""
    value = item[1] if isinstance(item, tuple) else item
    if not isinstance(value, str):
        return ""
    return (urlsplit(value).hostname or "") if "://" in value else value


def interleave_by_host(items: list) -> list:
    """The items in turns by host, each host's items in their original order.

    A worker keeps `window_size` requests in flight but only its share of connections per host. In a sorted list
    one host's items are contiguous, so a host with many items filled the whole window with requests waiting for
    that host, and the other hosts waited behind them.
    """
    groups: dict[str, deque] = {}
    for item in items:
        groups.setdefault(_request_host(item), deque()).append(item)
    turns = deque(groups.values())
    result = []
    while turns:
        group = turns.popleft()
        result.append(group.popleft())
        if group:
            turns.append(group)
    return result


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
            r'cluster', r'namespace', r'pod', r'deployment',

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

    @staticmethod
    def _matcher(patterns: list[str]) -> re.Pattern:
        return re.compile("|".join(f"(?:{pattern})" for pattern in patterns), re.IGNORECASE)

    @staticmethod
    def _match_target(url: str, scope=()) -> str:
        """The URL without query string or fragment, and without the configured domain in its host name.

        The configured domain is in every URL of a scan, so a pattern it contains (`key` in keystone.example, `acl`
        in miracle.example) would rank every URL high and leave a URL limit to the alphabet.
        """
        target = url.split("#", 1)[0].split("?", 1)[0]
        scheme, separator, rest = target.partition("://")
        authority, slash, path = rest.partition("/")
        host, colon, port = authority.partition(":")
        for root in sorted(scope, key=len, reverse=True):
            if root and (host == root or host.endswith("." + root)):
                host = host[:-len(root)]
                break
        return f"{scheme}{separator}{host}{colon}{port}{slash}{path}"

    def prioritize_urls(self, urls: Union[list[tuple[str, str]], list[str]], limit: int, scope=()) -> Union[list[tuple[str, str]], list[str]]:
        """Prioritize network and internal URLs based on likelihood of credential exposure."""

        FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL

        if not urls:
            return []

        script_patterns = self._get_critical_script_url_patterns()
        # The pattern lists are regular expressions (e.g. r'\.js$', r'dev\.'); match them as such,
        # against the URL without query string or fragment.
        internal_match = self._matcher(self.get_internal_url_patterns()['internal_pattern'])
        high_match = self._matcher(script_patterns['high_priority'])
        medium_match = self._matcher(script_patterns['medium_priority'])

        is_internal = isinstance(urls[0], str)
        url_type = "Internal" if is_internal else "Network"
        # Sorting makes the selection under a limit independent of discovery order.
        urls = sorted(urls)

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
                if internal_match.search(self._match_target(url, scope)):
                    high_priority.append(url)
                else:
                    low_priority.append(url)

        else:
            for url_obj in urls:
                origin_url, script_url = url_obj
                if script_url in seen_urls:
                    continue
                seen_urls.add(script_url)
                target = self._match_target(script_url, scope)
                if high_match.search(target):
                    high_priority.append(url_obj)
                elif medium_match.search(target):
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
            # New lists, so that the counts below are those of the selection, not of the input.
            remaining = limit - high_count
            medium = medium_priority[:remaining]
            low = low_priority[:remaining - len(medium)]
            result = high_priority + medium + low

            final_high, final_med, final_low = high_count, len(medium), len(low)

            logging.info(FY + f"\nFinal Selection:"
                              f"\n├── Selected URLs: {len(result):,}"
                              f"\n├── Distribution:"
                              f"\n│   ├── High Priority: {final_high:,} ({final_high / len(result) * 100:.1f}%)"
                              f"\n│   {'├── Medium Priority: ' + str(final_med) + f' ({final_med / len(result) * 100:.1f}%)' if not is_internal else '│'}"
                              f"\n│   └── Low Priority: {final_low:,} ({final_low / len(result) * 100:.1f}%)"
                              f"\n└── Limit: {limit:,}\n" + S)

        return result[:limit]
