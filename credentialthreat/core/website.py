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


BINARY_EXTENSIONS = frozenset((
    "jpg", "png", "gif", "jpeg", "bmp", "webp", "woff2", "woff", "ico", "svg", "mp3", "mp4",
    "mpeg", "mpg", "avi", "zip", "rar", "tar", "gz", "pdf", "ttf", "exe", "xml", "app",
))


def canonical_url(value: str) -> str | None:
    """One spelling per fetchable page: http(s) only, no userinfo or fragment, '/' for an empty path."""
    try:
        url = URL(value)
        if url.scheme not in ("https", "http") or url.raw_user is not None or url.raw_password is not None:
            return None
        host = dns_name(url.raw_host or "")
        if not host:
            return None
        return str(URL.build(scheme=url.scheme, host=host, port=url.explicit_port if not url.is_default_port() else None,
                             path=url.raw_path or "/", query_string=url.raw_query_string, encoded=True))
    except (ValueError, UnicodeError, TypeError):
        return None


def is_binary_url(value: str) -> bool:
    """True when the URL path ends in a file extension that never holds scannable text."""
    try:
        name = URL(value).path.rsplit("/", 1)[-1]
    except (ValueError, UnicodeError, TypeError):
        return False
    return "." in name and name.rsplit(".", 1)[-1].lower() in BINARY_EXTENSIONS


# Static (`import ... from`, `export ... from`, `import "x"`) and dynamic (`import("x")`) ES module imports whose
# specifier a browser loads without an import map: relative to the script (./, ../, /) or an absolute http(s) URL.
MODULE_IMPORT = re.compile(r"""(?:\b(?:from|import)\s*|\bimport\s*\(\s*)(["'])((?:\.{0,2}/|https?://)[^"'\s]+)\1""")


def module_imports(script: str) -> list[str]:
    """Literal module specifiers a browser would fetch for this script, in order of appearance."""
    return [match.group(2) for match in MODULE_IMPORT.finditer(script)]


def report_origin(value: str) -> str:
    """Exclude userinfo, paths, query strings and fragments from findings."""
    try:
        url = URL(value)
        if url.scheme in ("https", "http") and dns_name(url.raw_host or ""):
            return str(url.origin())
    except (ValueError, UnicodeError):
        pass
    return "[unknown origin]"
