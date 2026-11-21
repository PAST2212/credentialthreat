# Real-site scans

The synthetic runs in the [throughput report](../scan-throughput/README.md) cannot show how real sites answer. Two authorized production domains were therefore scanned with the default settings, without `--limit`, as a user would run the CLI. Neither domain, nor any of their hostnames, URLs or matched values, is reproduced here.

- **Site A** is an online retailer behind a bot-management service.
- **Site B** is a travel company. Discovery returned 578 in-scope hosts. Most of them are internal, retired or not publicly reachable.

## Setup

Both scans ran on Windows 11 with Python 3.12.3 and aiohttp 3.11.10. The machine has 6 physical cores, so the scanner used 5 workers.

A harness outside the repository ran the unmodified CLI and recorded locally:

- per request: status, body size, duration, wait for a host slot, DNS and connect time, exception type and TLS verification message;
- per worker: CPU time spent parsing and matching, and event-loop lag;
- for the whole run: RSS of the process tree.

The harness gave each `fetch_text` call its own outcome counter and merged it afterwards, so the outcome of every single request is exact even with many requests in flight. The totals equal the CLI's own `requests:` lines. Response bodies and matched values were not stored.

## Site A: before and after the fixes

The first scan found eight defects. Commit `1c95618` fixed them, and commit `e68658b` addressed the review findings.

| Defect | Evidence before the fix |
| --- | --- |
| Bot challenges (HTTP 400 with the service's challenge header) counted as `ok` | 73% of the pages were challenges |
| Every challenge page loaded the service's script under a new URL | 55% of the resource requests and 92% of the bytes |
| The credential rules ran with `IGNORECASE` | About 1.5 s of CPU per MB of text, blocking a worker's event loop for up to 7.9 s |
| All matches were the Fetch API option `credentials: "same-origin"` | 22 of 22 candidates |
| A blocked event loop turned a connection that had succeeded into a connect timeout | Reproduced locally |
| RapidDNS answers anonymous queries with 100 records only | 100 of more than 10,000 records |
| Modules that scripts load only through `import` were never fetched | 26 of 189 scripts on a category page |
| The outcome `connection` merged DNS failures, blocked destinations and TLS errors | No way to tell the causes apart |

| Site A | Before | After |
| --- | ---: | ---: |
| Elapsed | 191.6 s | 63.6 s |
| Credential stage | 123.7 s | 5.5 s |
| Requests / body data | 2,569 / 446 MB | 2,251 / 107 MB |
| CPU time in the credential rules | 661 s | 35 s |
| Longest event-loop block | 7.9 s | 2.0 s |
| False positives | 22 | 0 |
| Imported modules found on the category page | 0 / 26 | 26 / 26 |
| Peak RSS of the process tree | about 570 MiB | about 570 MiB |

## Site B

Site B served no bot challenge. None of its responses carried a header of a bot-management service. Its apex domain redirected to the main website, inside the scope. Two hosts serve almost all scripts.

Run 1 used the scanner as shipped. Run 2 was an experiment that changed one thing: like the `coverage` subcommand, it added the public CA bundle that `requests` ships to aiohttp's default TLS context. The load stayed what the scanner generates by itself. Site B answered no request with HTTP 429.

| Site B | Run 1: as shipped | Run 2: public CA bundle added |
| --- | ---: | ---: |
| Elapsed | 75 s | 83 s |
| In-scope hosts from discovery | 578 | 578 |
| Start pages read / error status / not read | 31 / 142 / 405 | 40 / 149 / 389 |
| Pages requested (read / error status / not read) | 586 (413 / 149 / 24) | 649 (464 / 157 / 28) |
| Resources requested, imported modules included | 935 (771 + 164) | 1,117 (821 + 296) |
| Resources read / failed on TLS | 766 / 137 | 1,085 / 0 |
| Unverified candidates (affected resources) | 202 (68) | 238 (83) |
| Requests / body data | 2,099 / 195 MB | 2,344 / 259 MB |
| Page stage: elapsed / worker CPU | 23.7 s / 87 s | 28.0 s / 88 s |
| Event loop blocked per page worker | 15–17 s | 16–17 s |
| Peak RSS of the process tree | 702 MiB | 724 MiB |

Discovery: crt.sh answered with 2,671 certificate records and 573 in-scope hosts. RapidDNS stated 949 records and returned 100 of them, with 56 hosts. Five of these 56 hosts were missing from crt.sh. An anonymous request for the second RapidDNS result page returned the same 100 rows.

Of the 405 start pages not read in run 1, 276 failed DNS, 77 timed out while connecting and 32 failed TLS. A sequential check afterwards confirmed the first two groups. None of the 276 names resolved, and 75 of the 77 hosts still accepted no TCP connection within 10 s. 133 hosts answered HTTP 403 to the scanner. These were default responses of load balancers and CDNs, and two samples also answered 403 in a browser.

### Defects found

| Defect | Evidence |
| --- | --- |
| On Windows, the website stages trust only the root certificates that Windows has already installed. Python's `ssl` module reads the Windows store but does not download missing roots, as Windows itself does on demand. The two script hosts send their chain with an extra self-signed root first. OpenSSL picks that root and stops, although a path to an installed root exists through a cross-certificate. | Run 1 lost 137 resources to `self-signed certificate in certificate chain`, among them every script on the two script hosts. Of the 20 in-scope scripts a browser loads on the home page, run 1 read 1. With the public CA bundle, run 2 read 319 more resources, 15 more hosts passed TLS, and 12 of the 20 scripts were read. The `coverage` subcommand already adds this bundle. |
| The page stage is bound by CPU work on the event loop | The five page workers used 87 s of CPU in a 24 s stage. Matching took 58 s of it and HTML parsing 19 s. Each worker's event loop was blocked for 15–17 s, which lengthened every request's wait for a host slot (90th percentile 7.8 s). In isolation, matching costs 0.29 s per MB. 27% of that is the `CASE_FOLD` translation, which takes more than ten times as long as `str.lower()`. In the scan, with five workers busy, matching took 0.41–0.47 s per MB. |
| Start pages are fetched twice | The link stage reads each host's start page only for its links. The page stage requests the same URL again for resources and matching: 168 of 586 page requests in run 1 and 179 of 649 in run 2. |
| The assignment rule matches across object properties | `withCredentials:this.withCredentials,requestType:"…"` yields a `credentials` candidate. The rule allows the field name inside a longer identifier, and its separator admits commas and identifier characters. The match therefore runs into the value of the next property. This caused 10 candidates in each run. |
| One page template produces most of the report | 62 pages on four white-label hosts each yield three rows (72 pages on five hosts in run 2). Two are AWS access-key IDs inside the `X-Amz-Credential` parameter of presigned S3 URLs. The third is a widget token. These rows account for 186 of 202 candidates in run 1 and 216 of 238 in run 2. The report keeps only origins, so the rows cannot be told apart. |
| The log of the final URL selection is wrong | Prioritization printed `High Priority: 586 (100.0%)` and `Low Priority: 445` for a selection with 141 high-priority URLs. The code takes the high-priority list as the result and then extends it, so the log counts every selected URL as high priority. The selection itself is correct. |

The first defect is fixed. Every connector now verifies certificates against the system's roots plus the public CA bundle, the same trust that run 2 used. With the previous context a request to each script host failed TLS, and with the new one both requests received HTTP responses. The scan was not repeated, because run 2 had already measured this configuration.

No candidate in either run was a secret. Besides the classes above, the candidates were public identifiers: a map provider's public token (`pk.` followed by a JWT-shaped string) and a client-side API key of an identity service. The rest were enumeration-like words and an ID in code that is commented out. The candidates were classified by field name, length, character classes and JWT claim names. No value was printed.

### Coverage of scripts

Two pages were loaded in a browser, and the scripts recorded by `performance.getEntriesByType("resource")` were compared with the URLs the scanner requested. The browser was not given cookie consent.

| Page | In-scope scripts in the browser | Read in run 1 | Read in run 2 |
| --- | ---: | ---: | ---: |
| Home page | 20 | 1 | 12, 3 of them through module imports |
| A destination page that is not linked from any start page | 28 | 8 | 21, 5 of them through module imports |

The scanner did not parse the destination page itself. Its scripts were read where other pages referenced them.

Run 2 missed 8 scripts on the home page and 7 on the destination page:

- Tag-manager scripts. The tag manager builds their URLs at runtime.
- Widgets that other scripts load at runtime under computed paths, and the modules these widgets import.
- A URL template with a country placeholder.
- A bare filename that is joined to a base path at runtime.
- An absolute URL that appears as a string in another script, which loads it itself.
- A script referenced by a `<link>` element that is created at runtime.

None of the scripts missed on the destination page appears in that page's HTML.

The module imports worked as intended. 164 imported modules in run 1 and 296 in run 2 were requested, and all of them were read.

### Checked and ruled out

- **Event-loop stall in the link stage.** In run 1, the event loop of every link worker stalled for 3.5–3.7 s at the same moment, while these workers used little CPU. Neither run 2 nor five link-stage processes started outside the pool reproduced it. At most one connect timeout may have resulted from it.
- **Charset.** Four responses declared ISO-8859-1 and were decoded as UTF-8, which drops their non-ASCII letters. The credential rules match ASCII only.
- **Retries.** Six hosts answered HTTP 503 every time and were tried three times each, as designed. Thirteen to eighteen redirects leading out of scope were skipped.
- **Request rate.** Pacing applies per worker, so all workers together sent up to 69 requests in one second to one host. The pacer allows each worker 25 requests per second to a host, which adds up to 125 for five workers. The connection budget, by contrast, is shared by all workers.

## Open limits

- Scripts whose URLs are computed at runtime are not found. On Site B these are a third of the in-scope scripts on the home page.
- Pages are found only through links on the start pages.
- Bot-management services other than Kasada and Cloudflare are not recognized. A challenge from another service counts as an error status, and its body is scanned like any other error page.
- Peak RSS reached 724 MiB with five workers. The workers alone took about 530 MiB during the link stage, before any large page was parsed.

The harness is not part of the repository.
