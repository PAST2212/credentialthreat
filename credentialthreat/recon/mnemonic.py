"""Anonymous PassiveDNS coverage for the supplied host's historical A records."""

from credentialthreat.core.discovery import UnexpectedFormat


NAME = "mnemonic"
PER_MINUTE = 10
PER_DAY = 1000


def request(domain, until):
    return f"https://api.mnemonic.no/pdns/v3/{domain}", {"rrType": "a", "limit": 1}


def count(payload, domain):
    if not isinstance(payload, dict) or payload.get("responseCode") != 200:
        raise UnexpectedFormat
    total, rows = payload.get("count"), payload.get("data")
    if type(total) is not int or total < 0 or not isinstance(rows, list):
        raise UnexpectedFormat
    size = payload.get("size")
    if type(size) is not int or size != len(rows) or len(rows) != min(total, 1):
        raise UnexpectedFormat
    if rows:
        row = rows[0]
        if not isinstance(row, dict) or row.get("rrtype") != "a" or not isinstance(row.get("query"), str):
            raise UnexpectedFormat
        if row["query"].lower().rstrip(".") != domain:
            raise UnexpectedFormat
    return total, "exact"
