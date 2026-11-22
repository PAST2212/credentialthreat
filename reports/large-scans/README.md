# Large real-site scans

The [real-site scans](../real-site-scans/README.md) covered two domains with a few thousand requests each. This report scales the same method up: scans with more than 100,000 requests, to find defects that only appear at that size. Neither the domains nor any of their hostnames, URLs or matched values are reproduced here.

- **Site C** is a manufacturing group. Its discovery and start pages were scanned.
- **Site D** is a university. Its discovery and start pages were scanned.
- **Site E** is a large online retailer. It was scanned in full before the fixes (run 1) and again after them (run 3).
- **Group F** is seven large technology companies, Site E among them, configured together as one scan (run 2).

## Setup

All scans ran on Windows 11 with Python 3.12.3 and aiohttp 3.11.10, on 6 physical cores, so the scanner used 5 workers. The CLI ran with its defaults, including `--limit` 100,000.

The harness from the real-site scans recorded every request, CPU-heavy step, event-loop lag and the RSS of the process tree locally, without bodies or matched values. It also saved the discovery result, so run 3 scanned exactly the 16,029 hosts that run 1 scanned.

## Defects found and fixed

| Defect | Evidence | Commit |
| --- | --- | --- |
| crt.sh queries were cut off after 30 s | crt.sh answered Site C after 14 to 64 s and ends a query itself with HTTP 504 after 120 s. The scan fell back to 15 hosts from RapidDNS instead of 1,525. | `fd685a6` |
| Discovery depended on two sources that fail on large domains | crt.sh answered every query with HTTP 502 for minutes; RapidDNS serves 100 rows without an account. AnubisDB, found through a GitHub code search for the request strings of both sources, added 1,903 hosts on Site C and 15,173 on Site E. [Source evaluation](../discovery-sources/README.md) | `8ff9f9c`, `334a1bf` |
| Anubis proof-of-work challenges counted as `ok` | Anubis answers with HTTP 200. On Site D, 2,074 of 2,398 start pages read were the challenge, each about 7 KB with 0 to 9 links. An honest user agent got the same challenge. | `f57d7c1` |
| Header lines over 8,190 bytes made a page unreadable | aiohttp rejected an 8,249-byte `Content-Security-Policy` with a `ClientResponseError`, counted as `error`. The page was lost with its links, and so were two login hosts that redirect to it. | `2f3a439` |
| A value repeated in one text became one row per occurrence | Run 1 reported 20,349 candidates in 329 texts, up to 624 in one page. A page fetched again held one value in 151 links. The report redacts values, so these rows were identical. | `e430275` |
| The JWT rule matched any base64url JSON with dots | The repeated value was a signed link parameter with the header `{"v":"1"}`. A JWS or JWE header always names its algorithm, so the rule now requires `"alg":`. The first version of that rule began with a lookahead and took 9.5 s on a 40 KB base64 run; it now starts with its literal again. | `71246f6`, `4690372` |
| URL priority patterns matched the scanned domain itself | On Site E a pattern contained in the domain ranked all 5,714 resources high, so a URL limit would have selected alphabetically. | `5814864` |
| Answers that are not HTTP counted as `error` | Push and VPN endpoints answer on port 443 with binary data. Run 1 counted 12 link-stage requests as `error`, these answers and the header-limit losses in one bucket. Such answers are now `invalid response`. | `43093d2` |
| Every `<link href>` was followed, including translations | Pages list their translations as `rel="alternate" hreflang`: 108 on one help page next to three stylesheets. In run 2, 80,643 of 91,570 resource URLs were such HTML pages, 32,937 on one host. A page and three of its translations carried the same `api_key` value. A first fix followed only the `<link>` rels a browser loads; run 3 showed that it also dropped two blog feeds whose matches appeared nowhere else, so only translations are skipped now. | `f908497`, `2b07e74` |
| One host's URLs filled a worker's whole window | Lists are sorted, so a host's URLs are contiguous, and a worker sends only 5 requests per host at once. In run 2, the URLs of a host that answered in about 10 s held every window: for 18 minutes the resource stage completed 150 instead of about 2,000 requests per minute. A 50-item window now holds a median of 7 hosts instead of 1. | `389596c` |

## Checked and ruled out

- **Connect timeouts.** On Site C, 398 of 569 resolvable hosts timed out while connecting. None of 40 sampled hosts accepted a TCP connection within 10 s in a sequential check. On Site E such hosts took 64% of the link stage's request time; they do not answer.
- **DNS throughput.** The link stage resolved names in a median of 2 s on Site D. A 50-thread resolver pool made each lookup slower, not the stage faster: the system resolver handled about 60 to 70 lookups per second either way.
- **Throttling on Site E.** In run 1 the page stage ran at about 3,000 pages per minute for five minutes, then the main shop host answered with 503 and 429 and the stage took 21 minutes. The scanner sent at most 23 requests per second to that host before the first 503, well below what the pacer allows, and backed off as designed. Retries recovered 56 pages; 1,989 of 2,173 pages on that host were read. No other host waited behind it.
- **Read-timeout retries.** 9 of 12 requests with a read timeout in run 1 were answered on a retry.
- **Memory.** Run 1 peaked at 949 MiB and run 2 at 1,709 MiB for the process tree. The parent never exceeded 251 MiB, and handing a stage's results to it took 0.1 s.

## Site E before and after the fixes

| Site E, same 16,029 hosts | Run 1 (`334a1bf`) | Run 3 (`389596c`) |
| --- | ---: | ---: |
| Elapsed | 1,671 s | 642 s |
| Link stage / page stage / resource stage | 185 s / 1,254 s / 218 s | 233 s / 388 s / 11 s |
| Start pages read / outcome `error` | 303 / 12 | 304 / 0 (`invalid response` 8) |
| Pages requested (read) | 17,378 (17,105) | 16,744 (16,662) |
| Pages skipped after HTTP 503 or 429 | 146 | 0 |
| Resources requested (read) | 5,714 (5,645) | 331 (295) |
| Requests in all website stages | 39,121 | 33,104 |
| Unverified candidates (affected texts) | 20,349 (329) | 132 (119) |
| Peak RSS of the process tree | 949 MiB | 1,027 MiB |

The start pages linked 16,744 pages in run 3 and 17,378 in run 1, because the site changed between the runs. The page stage was 3.2 times as fast: the main shop host throttled again, but its pages now took turns with the other hosts instead of forming the stage's last twelve minutes, and no page was given up after a 503 or 429. The 12 `error` outcomes of run 1 were non-HTTP answers and pages behind the long header; run 3 had none.

Run 3 used the first, stricter `<link>` filter. Of run 1's 5,714 resources, 4,581 had no file extension, 61% of them with a language code in the path; all 149 scripts of run 1 were requested in run 3 as well. The stricter filter also dropped two blog feeds whose two `dbuser` matches appeared nowhere else, and that is why `2b07e74` now skips only translations. A scan with the final code therefore fetches feeds, markdown copies and the other link targets again, somewhat more than run 3's 331 resources. Eleven `aws_keys` matches of run 1 were in translations of one glossary page; run 3 read the original page and matched it there.

Of the 132 candidates in run 3, 108 are JWT-shaped strings whose header names an algorithm; the signed link parameter and its repetitions are gone. Values were not stored, so the candidates were not classified further.

## Group F

Run 2 used the fixes up to `4690372` and seven domains. Discovery took 43 s and returned 70,339 in-scope hosts. The resource stage was stopped after the defects above had been measured, because the translations it was fetching would have taken hours longer.

| Group F, run 2 | Requests | Elapsed | Worker CPU | Body data | Matching |
| --- | ---: | ---: | ---: | ---: | ---: |
| Link stage | 70,339 | 1,050 s | 280 s | 260 MB | 61 s |
| Page stage | 26,140 | 1,701 s | 3,588 s | 6,954 MB | 2,140 s |
| Resource stage, until stopped | 17,775 of 91,570 | 1,579 s | | 5,632 MB | 1,667 s |

The scan completed 114,254 requests. Of the 70,339 hosts, 42,866 did not resolve and 22,761 accepted no connection.

## Open limits

- **Matching binds the page stage to the CPU.** At 0.3 s per MB it took 2,140 of 3,588 CPU seconds in run 2's page stage, and each page worker's event loop was blocked for 490 to 730 s in total, up to 7.7 s at once.
- **crt.sh received several queries per batch.** Run 2 sent seven within 43 s; crt.sh publishes 5 per minute. None failed. Each provider now pauses between domains according to its published rate.
- **Pages were found only through the start pages' links.** AlienVault OTX now adds page URLs; see the [source evaluation](../discovery-sources/README.md#url-sources).
- **Bot-management services** other than Kasada, Cloudflare and Anubis are not recognized.
- Run 2 did not finish its resource stage, so its candidates are not reported here.
