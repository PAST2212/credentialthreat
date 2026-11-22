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
- **URL Prioritization**: URLs are prioritized based on their likelihood of containing sensitive data. The patterns are matched without the configured domain, so a domain such as keystone.example, which contains the pattern `key`, does not rank all of its URLs high
- **Pattern Categories**:
  - High-Risk Patterns (API keys, tokens, passwords)
  - Cloud Service Credentials
  - Database Connection Strings
  - Authentication Tokens
  - Infrastructure Secrets

   
### CSV Output
The CLI creates `Credential_Leak_Candidates_Redacted_YYYY-MM-DD.csv` in `credentialthreat/data/output/`. Each semicolon-delimited row represents a matched value in a resource. The four columns contain the page origin, resource origin, registered domain of the page, and matched categories. Rules matching exactly the same span share a row, for example `Unverified api_key + aws_keys [REDACTED]`. A value that occurs several times in one resource gets one row, because the redacted rows would otherwise be identical: one production page carried the same signed link parameter in 151 links. Existing rows in a daily report keep their original counts.

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
- `--limit`: Maximum number of pages to scan, and separately of other resources such as scripts (default: 100000). See [Website scanner](#website-scanner) for how it is applied.

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

The three website-fetch stages and discovery verify HTTPS certificates against the system's root certificates plus the public CA bundle that `requests` ships. The bundle matters on Windows: Python reads only the roots Windows has already installed and does not download missing ones on demand, as Windows does. Without the bundle, a valid certificate chain that needs such a root failed as `TLS`. On one production site this skipped 137 resources, among them every script on its two script hosts. If you configure an explicit CA store with `SSL_CERT_FILE` or `SSL_CERT_DIR`, the scanner uses it instead of the bundle. The website stages follow a redirect only when its target lies inside the configured scope, for at most three hops, and each hop passes the same address and certificate checks. A redirect to any other host is never requested. Relative links on a redirected page resolve against the final page. Discovery providers receive the domain names they are asked to look up.

Website requests that receive HTTP 429 or 503 are repeated up to two times after the delay in `Retry-After`, capped at 30 seconds. Read timeouts and dropped connections are also repeated. During link discovery, a host that does not accept a connection is not retried, because many discovered hosts are unreachable. The page and resource stages retry a connect timeout once. A worker busy parsing or matching a large response can let a connection that succeeded run out its connect timeout. For a host that is really unreachable, the retry costs one more connect timeout. The retry does not use up the attempts for throttling and read timeouts. A request that never connects is reported by cause: `DNS`, `destination blocked`, `TLS`, `connect timeout` or `connection`. Each worker also paces its requests per host. A 429 or 503 pauses all of that worker's requests to the host for the announced delay and halves its rate for that host, and other responses raise the rate again, up to 25 requests per second. Several workers therefore slow down together instead of multiplying the load on a throttling server. The rate applies to each worker separately, so all workers together can send several times as many requests to one host. On a production site, five workers peaked at 69 requests in one second to a single host.

Responses with image, audio, video, font, PDF or archive content types are skipped without downloading the body, and a body is read up to 10 MB. Header lines may be up to 64 KiB long, because some sites send a `Content-Security-Policy` longer than the HTTP client's default limit of 8,190 bytes. A bot-management challenge is an error response with Kasada's `x-kpsdk-ct` header or Cloudflare's `cf-mitigated: challenge`, or a response that sets the `…-anubis-cookie-verification` cookie of Anubis, which answers with HTTP 200. It is neither read nor repeated, and the scripts it would load are not followed. The scanner does not try to solve such a challenge. Bodies of other error responses are still scanned. Each worker keeps at most 50 requests in flight, so one slow response does not hold back the others. Within each worker's list the hosts take turns: in a sorted list the 600 URLs of one host that answered in about 10 seconds filled every worker's 50 slots, and for 18 minutes the stage completed 150 instead of about 2,000 requests per minute. All workers together open at most 25 connections to one host, and each worker gets an equal share of at least two, so the load on a host does not grow with the number of CPU cores. A request beyond its worker's share waits before it is sent, so the wait does not count against its timeout. Peak memory depends on the number of worker processes and the requests in flight, not on the URL limit.

The scanner fetches each page once. Link discovery reads each host's start page and scans it like any other page: besides its links, it collects the resources the page references and matches the credential rules against its text. The page stage then fetches the other pages these links lead to. It collects the scripts, stylesheets, frames and other resources a page references, and matches the credential rules against the page text in the same request. It does not follow translations that a page lists as `<link rel="alternate" hreflang>`: one help page listed 108 translations of itself, and following them made translations 88% of a large scan's resource requests, with the same matches as the original page. Other `<link>` targets, such as feeds, are still fetched. The credential stage then fetches only those resources. It skips every URL the page stage already requested, for example a page's canonical link to itself, and every page that could not be read. Scripts often load further modules with `import ... from "./module.js"` or `import("/module.js")`. The credential stage fetches those modules in up to five more rounds, when the target is a literal URL or relative path in scope. It does not follow targets that are computed at runtime or that need an import map. On one production home page, 8 of the 20 in-scope scripts that a browser loaded were of that kind, for example those loaded by a tag manager. When the URL limit cuts imported modules, the same priority rules as for other resources decide which are kept. Matches in a page appear in the report with the page origin in both origin columns.

`--limit` caps two lists separately: the linked pages that link discovery found, and the other resources sent to the credential stage, imported modules included. Start pages are scanned during link discovery and count against neither cap. Pages never count against the resource cap, because they are not fetched again. A scan therefore requests one start page per host and at most twice the limit, plus redirect hops and retries.

After each website stage the CLI prints how many requests returned content and why the others were skipped, for example `Credential scan requests: ok=4, skipped=5 (HTTP 429=5)`. Error pages that were still scanned are counted apart from `ok`, for example `Network resource scan requests: ok=148, error status=22 (HTTP 403=17, HTTP 404=5), skipped=456 (bot challenge=456)`. The line is a warning when anything was skipped or answered with an error status. A URL limit keeps the same URLs on every run because candidates are sorted before prioritization. [Throughput and coverage measurements](reports/scan-throughput/README.md) · [Scans of two production sites](reports/real-site-scans/README.md) · [Scans with more than 100,000 requests](reports/large-scans/README.md)

The CLI shows the published request limits before discovery and in `python credentialthreat.py --help`. The sources for crt.sh and RapidDNS were checked on 19 November 2026, the source for AnubisDB on 21 November 2026 and the source for AlienVault OTX on 22 November 2026.

| Discovery service | Requests per minute | Requests per hour | Requests per day | Source |
| --- | --- | --- | --- | --- |
| crt.sh HTTPS (including JSON searches) | 5 per IP | unknown | unknown | [Operator statement, 9 June 2023](https://groups.google.com/g/crtsh/c/QXQFoy331pE) |
| RapidDNS web search (`/s/{domain}`) | 30 per public IP | unknown | unknown | [RapidDNS site usage guide](https://rapiddns.io/help/usage) |
| AnubisDB API (`/subdomains/{domain}`) | 360 per source IP (60 per 10 seconds) | unknown | unknown | [Anubis-DB README, Limits](https://github.com/jonluca/Anubis-DB#limits) |
| AlienVault OTX URL list (`/api/v1/indicators/domain/{domain}/url_list`, without API key) | unknown | unknown | unknown | [OTX API documentation](https://otx.alienvault.com/api) |

`unknown` means the cited provider material gives no separate quota for that period. Clients behind the same public IP share the minute quota. Each provider queries the configured domains one after another, with a pause that keeps it within its published rate: 12 seconds for crt.sh, 2 seconds for RapidDNS, 0.2 seconds for AnubisDB, and 1 second for AlienVault OTX, which publishes no limit. Discovery therefore takes about 12 seconds per configured domain.

The CLI queries crt.sh, RapidDNS and AnubisDB for host names and AlienVault OTX for page URLs for each configured domain, then collects internal links from the in-scope hosts. It reports query counts for each provider. `hits` means at least one in-scope result, `empty` means the provider confirmed zero records, and `filtered` means it returned records but none qualified. `errors` includes DNS failures, timeouts, HTTP errors and unrecognized responses, even with HTTP 200. For a domain with many certificates crt.sh can take more than a minute to answer, and it ends a query itself with HTTP 504 after 120 seconds. The CLI therefore waits up to 150 seconds for crt.sh and 30 seconds for RapidDNS and AnubisDB. A query that fails with an HTTP 5xx status is repeated once, after 15 seconds for crt.sh and 5 seconds for RapidDNS and AnubisDB. If any query fails, the CLI writes the available results and exits with code 1. Without an account RapidDNS lists 100 records and states the full total. The summary then adds a warning such as `partial=1 (100 of 10970 records)`, and the CLI repeats it after writing the report. The exit code does not change, because the cap applies to every large domain. A completed scan with only confirmed empty responses exits with code 0.

AnubisDB stores subdomains that recon tools submit to it. The scanner only reads from it and never submits the names it discovers. On a domain where crt.sh and RapidDNS found 1,539 hosts, AnubisDB added 1,903, and link discovery read 107 more start pages than the 71 from the other two sources. [Evaluation of keyless discovery sources](reports/discovery-sources/README.md)

AlienVault OTX lists URLs it has seen under a domain. Link discovery finds only pages that a start page links to, so these URLs go straight to the page stage, where `--limit` applies. On a large retailer, 146 of 200 OTX URLs that the crawl had never requested were readable pages. OTX answers this list without an API key but publishes no limit for it, and deep pages are slow, so the scanner reads at most four pages of 500 URLs per domain, one second apart. If a later page fails, the URLs already read are kept and the summary reports the answer as partial, for example `partial=1 (2000 of 40565 records)`.

When no eligible pages or resources remain, the CLI writes the report immediately and skips the remaining worker pools. In a Linux benchmark with two workers, this saved 5.50 MiB of proportional memory in the empty final stage. [Benchmark setup and timing](reports/empty-stage/README.md)

Website and discovery connections require public unicast addresses. If DNS returns a private or otherwise excluded address, the scanner skips the whole answer, even when it also contains a public address. This excludes internal-only sites and applies to cached answers and IP literals. Domain parsing uses the bundled public suffix list, including private suffixes.

## Changelog

For updates, please see the [Changelog](https://github.com/PAST2212/credentialthreat/blob/master/Changelog).

## Notes

### Author
Patrick Steinhoff - [LinkedIn](https://www.linkedin.com/in/patrick-steinhoff-168892222/)

### Additional Information
- Part of credential patterns are based on Bug Bounty Hunter h4x0r-dz project: [Leaked-Credentials](https://github.com/h4x0r-dz/Leaked-Credentials)
