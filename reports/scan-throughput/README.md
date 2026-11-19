# Website scan throughput and coverage

Large scans took long. More parallelism seemed to raise memory use and instability, and some pages seemed to be skipped. These measurements trace each symptom to a cause and compare the scanner before and after the fixes.

## Setup

**Synthetic site.** A local HTTPS server with a throwaway test CA served five hosts. `example.com` and `shop.example.com` had 1,500 pages each. `static.example.com` held 20 shared scripts, referenced only as protocol-relative `//static.example.com/...` URLs. `www.example.com` redirected to `example.com`, and one host was unreachable.

The pages carried 440 unique synthetic credentials:

- in every 10th page script,
- inline in every 25th page,
- in all 20 shared scripts.

Every 20th page linked a 1 MiB PDF, and half the pages were also linked with a `#reviews` fragment.

- **Run A:** no server limits.
- **Run B:** the server answered more than 40 requests per second per host with HTTP 429 and `Retry-After: 1`, and every 100th page responded after 10 seconds.

A resolver patch mapped every name to loopback, so no request left the machine. The test machine ran Windows 11 with Python 3.12.3 and aiohttp 3.11.10. It had 6 physical cores, so the scanner used 5 workers, and 13.9 GB RAM.

**Production domain.** One authorized production domain was scanned with `--limit 3000`. The harness recorded status, content type, size, duration and exception type for every request, locally. The domain and its URLs are not reproduced here.

## Defects found

| Defect | Evidence before the fix |
| --- | --- |
| The binary-file filter regex contained a stray apostrophe and never matched | Run A downloaded 302 PDFs (317 MB) and parsed them as HTML |
| Protocol-relative URLs were dropped in the link stage and rewritten to `https://page-host/other-host/...` in the resource stage | All 20 shared-script credentials were missed |
| Fragment and root-slash spellings were fetched separately, and the root domain appeared twice in the host list | 51% of the requests in Run A were duplicates. The 420 credentials found were reported as 480 candidates |
| HTTP 429 and 503 bodies were treated as content. The retries in the link and resource stages were dead code, because every exception was caught first | Run B received 1,240 responses with HTTP 429, logged nothing and missed 55 credentials |
| All redirects were skipped, including those inside the scope | 8 of 11 responding start pages on the production domain redirected within the scope, among them the main website |
| Chunk calibration measured RSS after a live sample scan, ignored the worker count and fetched the first 100 URLs of each stage twice | The resource stage ran 4,661 URLs in one chunk on one of five workers |
| Batch processing waited for the slowest request in each batch of 50 | One slow page in a hundred added about 307 s to the resource stage in Run B |
| Prioritization treated regular expressions such as `\.js$` as plain substrings and kept set order | JavaScript was never preferred, and the URLs cut by `--limit` changed from run to run |
| `networksearch` could not be imported on its own (`networksearch → utils → networksearch`) | Import error in a fresh interpreter |
| Discovery did not repeat a query after a provider's 5xx response | crt.sh answered HTTP 502 and the run lost all hosts known only to crt.sh |

## Results

| Run A, no server limits | Before | After |
| --- | ---: | ---: |
| Elapsed | 282 s | 89 s |
| Planted credentials found | 420 / 440 | 440 / 440 |
| Reported candidates | 480 | 440 |
| Requests | 12,558 | 9,035 |
| PDF downloads | 302 | 0 |
| Peak RSS of the process tree | 424 MiB | 365 MiB |

| Run B, throttling and slow pages | Before | After |
| --- | ---: | ---: |
| Elapsed | 708 s | 283 s |
| Planted credentials found | 365 / 440 | 440 / 440 |
| HTTP 429 responses | 1,240, not reported | 554, retried; 1 page skipped and reported |
| Peak RSS of the process tree | 423 MiB | 366 MiB |

| Production domain, `--limit 3000` | Before | After |
| --- | ---: | ---: |
| In-scope hosts from discovery | 33 (crt.sh answered HTTP 502) | 74 (both providers answered) |
| Start pages read / skipped as redirects | 3 / 8 | 21 / 0 |
| Pages / resources scanned | 9 / 19 | 510 / 1,573 |
| Resources skipped | not reported | 13 (12 connect timeouts, 1 binary) |
| Unverified candidates | 0 | 5 in 2 resources |
| Elapsed / peak RSS | 110 s / 409 MiB | 254 s / 555 MiB |

The production numbers differ partly because crt.sh failed during the earlier run. The discovery retry did not trigger in the later run. That run used the code before the last change, which only moved the wait for a per-host request slot in front of the HTTP client. The number of connections to the host stayed the same, so the production scan was not repeated.

### Fetching each page once

A later change matches the page text in the resource stage, so the credential stage no longer fetches the pages again. Both synthetic runs were repeated with that change on the same site and machine:

| Synthetic site | Pages fetched twice | Pages fetched once |
| --- | ---: | ---: |
| Run A elapsed | 89 s | 65 s |
| Run A requests (repeated requests) | 9,035 (3,009) | 6,032 (6) |
| Run B elapsed | 283 s | 223 s |
| Run B requests / HTTP 429 responses | 9,586 / 554 | 6,500 / 469 |
| Planted credentials found, Run A and Run B | 440 / 440 | 440 / 440 |
| Peak RSS of the process tree | 365–366 MiB | 364–366 MiB |

In Run B one resource stayed throttled after three attempts and appeared in the skip report. It carried no planted credential. The production domain was not scanned again with this change.

## Why each part is needed

The intermediate runs show why the fixes depend on each other:

- **Pacing per host.** Spreading the work over all workers without it raised the load on each host. Run B then found only 279 of 440 credentials and received 9,436 responses with HTTP 429. Before, the resource stage had been polite only because it ran on a single worker. With a 429 or 503 the pacer now pauses the host and halves its rate within each worker, so independent workers settle below the server's limit.
- **One chunk per worker.** With four contiguous chunks per worker, every chunk ended with its slowest request. On the production domain, each worker spent over half of the credential stage with only one or two requests in flight. Dealing URLs round-robin into one chunk per worker leaves a single tail per worker.
- **Shared connection budget per host.** Round-robin chunks put every worker on the same host at the same time. Connect timeouts rose from 9 to 80. The workers now share a budget of 25 connections per host, and the count fell to 12.
- **Waiting before the HTTP client.** aiohttp counts the wait for a pooled connection against the 45-second request timeout. A request beyond its worker's share therefore waits before it reaches aiohttp.

## Remaining limits

- Pages were fetched in the resource stage and again in the credential stage. In Run A this accounted for 3,009 of 9,035 requests. A later change matches the page text in the resource stage and sends only the other resources to the credential stage, so each page is fetched once. [Measured effect](#fetching-each-page-once)
- Peak memory is dominated by the worker processes, at about 360–560 MiB for the process tree with five workers. Each worker holds at most 50 bodies of up to 10 MB at once.
- The scan follows links of the start pages only and does not execute JavaScript. Scripts loaded only from other scripts are not found.
- `--limit` applies to the pages and to the other resources separately. Since pages are no longer fetched again, they no longer count against the resource cap.
- One intermediate Windows run logged an asyncio `WinError 10022` while closing a TLS connection. The final runs did not reproduce it.
- The measurement harness is not part of the repository. The offline tests cover each behavior listed above.
