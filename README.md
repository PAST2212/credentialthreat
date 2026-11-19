# credentialthreat

Find leaked credentials and sensitive data (e.g., tokens, API keys) based on URL, Subdomain & JavaScript File Permutations.

**Current Version:** 2.01

## Features

### Key Features
- Subdomain Scan
- Internal URL Discovery
- Network Resource Detection (JavaScript, Configuration Files)
- Enhanced Credential Pattern Detection
- Smart URL Prioritization
- Multiprocessing based on CPU cores
- DDoS Prevention Instruments (e.g., time delays)
- Configurable URL Scan Limit (default: 100,000)

### Scanning Strategy
- **URL Prioritization**: URLs are prioritized based on their likelihood of containing sensitive data
- **Pattern Categories**:
  - High-Risk Patterns (API keys, tokens, passwords)
  - Cloud Service Credentials
  - Database Connection Strings
  - Authentication Tokens
  - Infrastructure Secrets

   
### CSV Output
The CLI creates `Credential_Leak_Candidates_Redacted_YYYY-MM-DD.csv` in `credentialthreat/data/output/`. Each semicolon-delimited row represents a matched value at one text position in a resource. The four columns contain the page origin, resource origin, registered domain of the page, and matched categories. Rules matching exactly the same span share a row, for example `Unverified api_key + aws_keys [REDACTED]`. Repeated values at different positions get separate rows. Existing rows in a daily report keep their original counts.

Reports identify origins by scheme, host and port. Paths, URL credentials, queries, fragments and matched values are omitted. The console summarizes targets by count. Discovery errors identify the provider or stage, exception type and HTTP status when available. Older reports can contain raw values and keep their original filenames.

A match can be a public identifier or a documentation example. Assess it against the owner's source and deployment records before treating it as an incident.

Run `python tests/measure_rules.py` to reproduce per-rule precision, recall and error locations on the labeled synthetic HTML corpus. [Benchmark results and labeling criteria](reports/website-scan-review/README.md#offline-precision-and-recall)

## Installation

Use Python 3.12 or later.

```bash
git clone https://github.com/PAST2212/credentialthreat
cd credentialthreat
pip install -r requirements.txt
```

## Usage

Basic usage (default setting):
```bash
python3 credentialthreat.py
```

Advanced usage (example command):
```bash
python3 credentialthreat.py --limit 200000
```

Options:
- `--limit`: Maximum number of URLs to be scanned (default: 100000)

## Updating

```bash
cd credentialthreat
git pull
```

If you encounter a merge error, try:
```bash
git reset --hard
git pull
```

## Configuration

### Passive coverage report

Run `python credentialthreat.py coverage example.com otto.de amazon.com` to report aggregate counts for those exact hostnames. Add `--samples 50` to repeat the measurement in round-robin order within the current UTC clock hour. Use `--source mnemonic` or `--source urlscan.io` to query one provider. The report uses only existing public observations. It makes read-only requests to the providers and leaves the website scanner idle. HTTPS verifies hostnames and certificate chains. If you configure an explicit CA store with `SSL_CERT_FILE` or `SSL_CERT_DIR`, coverage respects that selection.

| Source | Count | Anonymous limits |
| --- | --- | --- |
| mnemonic PassiveDNS | Historical A records for the exact hostname. The report reads the total even though it requests a single record. | 10 requests per minute and 1,000 per day. The public guide gives no hourly figure. [Provider guide](https://docs.mnemonic.no/service-integration-guides/passivedns/docs/public/01-public_api.html) |
| urlscan.io | Public scans whose final hostname matches exactly. The query requests the preceding 30 complete UTC dates. The provider may restrict anonymous history further. At the service's count cap, the report marks the total as a lower bound. | The CLI reads and prints the minute, hour and day quotas and remaining search requests for the current client. On 19 November 2026 the anonymous quota endpoint returned 30/minute, 100/hour and 500/day. [Search API](https://docs.urlscan.io/apis/urlscan-openapi/search/searchdatasource) · [Quota windows](https://docs.urlscan.io/pages/api-rate-limits) |

CSV goes to standard output. Quotas and time bounds go to standard error, so append `> coverage.csv` to save just the observations. Each row records the UTC time, sample, domain, provider, status, count, whether it is exact or a lower bound, and any error or skip reason. `empty` is a confirmed zero. `errors` marks a failed attempt and `skipped` an unsent query. Either makes the command exit with code 1. Repetition measures short-term availability and stability of reported counts.

The three-domain verification received 250 valid data responses during one UTC quota hour. [Live measurement and offline tests](reports/osint-coverage/README.md)

### Website scanner

Copy `credentialthreat/data/input/domains.example.txt` to `domains.txt` in the same directory. Enter one authorized DNS hostname per line. Each entry includes that host and its descendants. For example, `docs.example.com` excludes `example.com` and `shop.example.com`. The CLI rejects wildcard entries, public suffixes and URL-shaped entries. Git ignores the editable file.

The three website-fetch stages verify HTTPS certificates. They follow a redirect only when its target lies inside the configured scope, for at most three hops, and each hop passes the same address and certificate checks. A redirect to any other host is never requested. Relative links on a redirected page resolve against the final page. Discovery providers receive the domain names they are asked to look up.

Website requests that receive HTTP 429 or 503 are repeated up to two times after the delay in `Retry-After`, capped at 30 seconds. Each worker also paces its requests per host. A 429 or 503 pauses all of that worker's requests to the host for the announced delay and halves its rate for that host, and other responses raise the rate again, up to 25 requests per second. Several workers therefore slow down together instead of multiplying the load on a throttling server. Read timeouts and dropped connections are also repeated. A host that does not accept a connection is not retried. Responses with image, audio, video, font, PDF or archive content types are skipped without downloading the body, and a body is read up to 10 MB. Each worker keeps at most 50 requests in flight, so one slow response does not hold back the others. All workers together open at most 25 connections to one host, and each worker gets an equal share of at least two. A request beyond its worker's share waits before it is sent, so the wait does not count against its timeout. The load on a host therefore does not grow with the number of CPU cores. Peak memory therefore depends on the number of worker processes and the requests in flight, not on the URL limit.

After each website stage the CLI prints how many requests returned content and why the others were skipped, for example `Credential scan requests: ok=4, skipped=5 (HTTP 429=5)`. The line is a warning when anything was skipped. A URL limit keeps the same URLs on every run because candidates are sorted before prioritization. [Throughput and coverage measurements](reports/scan-throughput/README.md)

The CLI shows the published request limits before discovery and in `python credentialthreat.py --help`. Provider sources were checked on 19 November 2026.

| Discovery service | Requests per minute | Requests per hour | Requests per day | Source |
| --- | --- | --- | --- | --- |
| crt.sh HTTPS (including JSON searches) | 5 per IP | unknown | unknown | [Operator statement, 9 June 2023](https://groups.google.com/g/crtsh/c/QXQFoy331pE) |
| RapidDNS web search (`/s/{domain}`) | 30 per public IP | unknown | unknown | [RapidDNS site usage guide](https://rapiddns.io/help/usage) |

`unknown` means the cited provider material gives no separate quota for that period. Clients behind the same public IP share the minute quota. The scanner paces provider batches and can send several domain requests within a batch.

The CLI queries crt.sh and RapidDNS for each configured domain, then collects internal links from the in-scope hosts. It reports query counts for each provider. `hits` means at least one in-scope result, `empty` means the provider confirmed zero records, and `filtered` means it returned records but none qualified. `errors` includes DNS failures, timeouts, HTTP errors and unrecognized responses, even with HTTP 200. A query that fails with an HTTP 5xx status is repeated once, after 15 seconds for crt.sh and 5 seconds for RapidDNS. If any query fails, the CLI writes the available results and exits with code 1. A completed scan with only confirmed empty responses exits with code 0.

When no eligible pages or resources remain, the CLI writes the report immediately and skips the remaining worker pools. In a Linux benchmark with two workers, this saved 5.50 MiB of proportional memory in the empty final stage. [Benchmark setup and timing](reports/empty-stage/README.md)

Website and discovery connections require public unicast addresses. If DNS returns a private or otherwise excluded address, the scanner skips the whole answer, even when it also contains a public address. This excludes internal-only sites and applies to cached answers and IP literals. Domain parsing uses the bundled public suffix list, including private suffixes.

## Changelog

For updates, please see the [Changelog](https://github.com/PAST2212/credentialthreat/blob/master/Changelog).

## Notes

### Author
Patrick Steinhoff - [LinkedIn](https://www.linkedin.com/in/patrick-steinhoff-168892222/)

### Additional Information
- Part of credential patterns are based on Bug Bounty Hunter h4x0r-dz project: [Leaked-Credentials](https://github.com/h4x0r-dz/Leaked-Credentials)
