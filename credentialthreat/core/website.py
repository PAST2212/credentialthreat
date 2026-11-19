from ipaddress import IPv4Address, IPv4Network, IPv6Network, ip_address
import re

import aiohttp
import tldextract
from yarl import URL


# Scope decisions and reporting use the bundled suffix list, including private suffixes.
SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

# Treat the whole special-purpose blocks conservatively across Python 3.12 patch versions.
IPV4_SPECIAL = (IPv4Network("192.0.0.0/24"), IPv4Network("192.88.99.0/24"))
IPV6_GLOBAL_UNICAST = IPv6Network("2000::/3")
IPV6_SPECIAL = (IPv6Network("2001::/23"), IPv6Network("2002::/16"), IPv6Network("3fff::/20"))


def _public_destination(host: str) -> bool:
    if not isinstance(host, str):
        return False
    try:
        address = ip_address(host)
    except ValueError:
        return False
    if not address.is_global or address.is_multicast:
        return False
    if isinstance(address, IPv4Address):
        return not any(address in block for block in IPV4_SPECIAL)
    return (address.scope_id is None and address in IPV6_GLOBAL_UNICAST
            and not any(address in block for block in IPV6_SPECIAL))


class DestinationBlocked(OSError):
    """The DNS answer failed the public destination check."""


class PublicDestinationConnector(aiohttp.TCPConnector):
    async def _resolve_host(self, host, port, traces=None):
        # In the pinned aiohttp this also returns literal IPs and DNS-cache hits.
        # Returning these same records avoids a second resolution before connecting.
        answers = await super()._resolve_host(host, port, traces=traces)
        if not answers or not all(_public_destination(answer["host"]) for answer in answers):
            raise DestinationBlocked("Destination requires public unicast addresses")
        return answers


def dns_name(host: str) -> str:
    try:
        name = URL.build(scheme="https", host=host.removesuffix(".")).raw_host or ""
    except (ValueError, UnicodeError):
        return ""
    if len(name) > 253 or not all(DNS_LABEL.fullmatch(label) for label in name.split(".")):
        return ""
    return name


def host_in_scope(host: str, domains: list[str]) -> bool:
    host = dns_name(host)
    return bool(host) and any(host == root or host.endswith("." + root) for root in domains if root)


def url_in_scope(value: str, domains: list[str]) -> bool:
    try:
        url = URL(value)
        return (url.scheme in ("https", "http") and url.raw_user is None and url.raw_password is None
                and url.port is not None and host_in_scope(url.raw_host or "", domains))
    except (ValueError, UnicodeError):
        return False


def report_origin(value: str) -> str:
    """Exclude userinfo, paths, query strings and fragments from findings."""
    try:
        url = URL(value)
        if url.scheme in ("https", "http") and dns_name(url.raw_host or ""):
            return str(url.origin())
    except (ValueError, UnicodeError):
        pass
    return "[unknown origin]"
