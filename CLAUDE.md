# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

## Commands

Run everything from the repository root. There is no build step.

- Full offline suite: `python -m unittest discover -s tests`
- One file: `python -m unittest discover -s tests -p "test_reports.py"`
- One test by name: `python -m unittest discover -s tests -k test_combined_categories`
- Rule precision/recall benchmark: `python tests/measure_rules.py`

Always go through `discover -s tests`. `test_rule_benchmark.py` imports `credential_corpus` and `measure_rules` as top-level modules, so a dotted `python -m unittest tests.test_x` run fails for it. The same goes for `http_doubles`, the shared response double: it streams `content.iter_chunked` like aiohttp, so build fake responses with it rather than mocking `response.text()`. The shutdown test that needs `fork` is skipped on Windows. `test/` (singular) is ignored legacy scratch and is not part of the suite.

## Architecture

### Website scan pipeline

`_run_scan` in `credentialthreat.py` runs these stages in order:

1. **Discovery** (`core/subdomainsearch.py`) runs in the parent process. It queries crt.sh and RapidDNS for every configured domain and keeps only in-scope hosts.
2. **Internal links** (`core/internallinksearch.py`) fetches each host's start page and collects its `<a href>` links. It also scans the start page as stage 3 scans other pages, through `ScanerNetworkResources.parse` and `scan_page`. Its worker returns `(links, resources, requested pages, redacted page candidates, outcomes)`. The CLI drops the requested pages from stage 3's input, so stage 3 never fetches a start page again.
3. **Network resources** (`core/networksearch.py`) fetches each page once. It collects script, link, iframe and other resource URLs, plus the targets of inline module imports (`website.module_imports`) and of `require`, `importScripts` and `loadScript`. It also matches the credential rules (`ScanerCredentials._findings`) against the page text. Its worker returns `(resources, requested pages, redacted page candidates, outcomes)`.
4. **Credentials** (`core/credentialsearch.py`) fetches each remaining resource and matches the credential rules against the response text. The CLI drops every URL that stages 2 and 3 requested, so no page is fetched twice, and merges the candidate lists of stages 2–4 before writing the report. Its worker returns `(candidates, outcomes, imports)`. `imports` lists the in-scope modules that 2xx JavaScript responses import. The CLI fetches new ones in further rounds on the same pool, at most `IMPORT_ROUNDS` (5). `_next_imports` drops every URL already requested and counts the rest against `--limit`. When the limit cuts them, `UrlPrioritizer` decides which are kept, as in the first round.

Stages 2–4 share one pattern:

- The parent deals the work round-robin into one chunk per worker with `utils.plan_chunks` and runs the chunks on a `multiprocessing` pool from `interrupt_handler.create_pool`. A chunk ends with its slowest request, so more chunks per worker would add idle tails. A real scan showed this: with four chunks per worker, each worker spent over half its time with only one or two requests in flight.
- Because every worker works on every host at once, the workers share one per-host connection budget: `utils.host_connections_per_worker` hands each worker an equal share of 25, at least two. Workers pass it to the scanners' `host_connections`. Against one real host, five workers without the budget lost 80 resources to connect timeouts. With it, they lost 12.
- Each chunk goes to a module-level `process_chunks_for_*` function, which calls `asyncio.run` on a scanner class constructed with `scope=domains`. Workers return their results plus a dict of request outcomes. The parent sums the outcomes and logs one `... requests: ok=N, error status=E (...), skipped=M (...)` line per stage. The `error status` part appears only when error pages were read.
- Inside a worker, `AsyncCancellationManager.run_window` keeps `window_size` requests in flight (a sliding window, not batches), so one slow response never holds back the others.
- The parent reads results through `GracefulKiller.pool_results`, which converts SIGINT/SIGTERM into `ScanInterrupted`.
- `UrlPrioritizer` in `core/utils.py` caps each stage's input at `--limit` and takes high-priority URL patterns first. Pages and the other resources are capped separately; pages never count against the resource cap. Start pages are not capped: stage 2 scans them before the page cap applies.
- When a stage has no input, the CLI skips its pool. When no pages and no resources remain, it writes the report straight away and skips the remaining pools. Tests cover this.

The workers have to survive multiprocessing:

- Worker functions must stay module-level and picklable. `configure_platform_settings` uses `spawn` with the Proactor loop on Windows and `fork` on POSIX.
- Workers ignore SIGINT and let the parent handle it.
- A worker must not let a `BaseException` escape: that kills the process without resolving its pool result. Convert it, as `process_chunks_for_networksearch` does.
- The pool size is the physical core count minus one.

### Fetching and URL handling

Every website request goes through `fetch_text` in `core/fetch.py`.

- It follows redirects only to targets inside the scope, for up to three hops. Without a scope it follows none.
- It retries 429 and 503 responses (honouring `Retry-After`, capped at 30 s), read timeouts and dropped connections. It does not retry other connection errors. It retries connect timeouts only up to `connect_retries`. The page and resource scanners pass 1 and the link scanner passes 0. CPU-bound work can block a worker's event loop past `sock_connect` (5 s). The expired timer then fires before the finished connection is processed, so a connection that succeeded becomes a connect timeout. `BlockedLoopTests` reproduces this by holding the loop inside a patched `loop.sock_connect`. In the link stage most connect timeouts are dead hosts. A retried connect timeout does not count against `MAX_ATTEMPTS`.
- `connection_failure` names the cause of a request that never got a response: `DNS`, `destination blocked`, `TLS` or `connection`. These names match the discovery reasons.
- Each scanner owns a `HostPacer`, which hands out the worker's per-host request slots (`connections`). Requests beyond the share wait in `pacer.slot` before reaching aiohttp, because aiohttp counts time spent waiting for a pooled connection against the 45 s total timeout. The pacer also paces requests per host. A 429 or 503 pauses the host and halves its rate, and other responses raise it again. Without it, the parallel workers multiplied the load on throttling servers and lost more pages than the old single-worker stage did. Tests inject a `FakeClock` (in `tests/http_doubles.py`) into `scanner.pacer`. Patching only `asyncio.sleep` leaves the pacer on the real clock.
- It skips binary content types without reading the body and cuts bodies at 10 MB.
- It skips a bot-management challenge without reading or retrying it and counts it as `bot challenge`. `is_bot_challenge` recognizes a non-2xx response with Kasada's `x-kpsdk-ct` header or Cloudflare's `cf-mitigated: challenge`. Each challenge page loads its script under a fresh URL. On one production site, following them made up 55 % of the resource requests.
- Bodies of other error responses are still returned for scanning, because debug pages can leak values. They count as `HTTP <status> read`, never as `ok`.
- Every call adds exactly one entry to the scanner's `outcomes` counter.

Scanners must not open requests any other way.

`PublicDestinationConnector` verifies TLS with `shared_tls_context` from `core/website.py` unless a caller passes its own `ssl` context. That context holds the system's roots plus the CA bundle from `requests`. `SSL_CERT_FILE` or `SSL_CERT_DIR` replaces the bundle. On Windows aiohttp's default context holds only the roots Windows has already installed, because Python does not download missing roots the way Windows does. With it, a chain that needs such a root failed as `TLS`, even though the server was fine. On one production site this hit both script hosts. Loading the bundle takes about 0.25 s, and each import round opens new connectors, so each process builds the context once.

Links and resource references are resolved with `urljoin` against the final page URL. `website.canonical_url` then reduces them to one spelling: http(s) only, no fragment or userinfo, and `/` for an empty path. `website.is_binary_url` drops binary file extensions. `website.resolve_reference` combines these steps with the scope check for page resources and imported modules alike. The CLI sorts the canonical page list before prioritizing it, so a URL limit is reproducible.

Import direction matters, because a test checks that each scanner module imports in a fresh interpreter:

- Scanner modules import `fetch`, `website` and `interrupt_handler`, never `utils`. `utils` imports `networksearch`, so the reverse import would bring back a circular import.
- `networksearch` also imports `credentialsearch` for the matcher, so `credentialsearch` must not import `networksearch`.

Exit codes are:

- `0`: the scan completed.
- `1`: any discovery query failed (the report is still written), a stage raised an error, or the scan was interrupted.
- `2`: `domains.txt` contains no domains.

### `coverage` subcommand

`credentialthreat.py coverage DOMAIN...` takes a separate path and never feeds the website scanner. `core/coverage.py` drives the providers in `recon/mnemonic.py` and `recon/urlscan.py`. Each provider is a plain module that exposes `NAME`, `request(domain, until)` and `count(payload, domain)`. The run stops at the end of the current UTC hour. CSV rows go to stdout and quotas and diagnostics to stderr.

### Discovery providers

A website-discovery provider subclasses `SubdomainProvider` in `core/discovery.py` and implements `_scrape_subdomains(session, domain) -> (record_count, hosts)`. Register it in `SUBDOMAIN_SERVICES` in `core/subdomainsearch.py`.

A provider that states its total can return `(record_count, hosts, stated_total)`. RapidDNS does this, because without an account it lists only 100 records. `QueryResult.available` holds the total. When it exceeds `records`, `QueryResult.partial` is true. `log_query_summary` then adds a `partial=N (...)` warning, and `_write_scan_report` repeats it after the report. A partial answer does not count as a failed query, so the exit code stays the same.

- Raise `UnexpectedFormat` for a response the provider does not recognize, even with HTTP 200. Do not return an empty set for it.
- Call `require_ok` for HTTP status checks.
- `observe` turns each query into a `QueryResult` in one of four states: `hits`, `empty` (a confirmed zero), `filtered` or `error`. The summary log and the exit code depend on those states.
- `SubdomainProvider._query` repeats a query once when it fails with an HTTP 5xx status, after the class's `retry_pause`. That pause is 15 s for crt.sh and 5 s for RapidDNS, which keeps the retry within their published per-minute limits. Tests patch `asyncio.sleep` to skip the pause.

`recon/dnsdumpster.py` and `recon/subdomaincenter.py` are legacy and not registered. Only a diagnostics test still imports them.

### Credential rules

Rules live in `ScanerCredentials.__init__`:

- `credential_pattern` matches a field name, an assignment operator and a quoted value, case-insensitively. `tests/measure_rules.py` reads this string. The values `same-origin` and `use-credentials` are excluded. The first is the Fetch API option `credentials: "same-origin"`, and on one production site it accounted for every match. The second is a CORS mode that another site assigned to `withCredentials`. The separator between field name and operator admits no comma, so `withCredentials:this.withCredentials,requestType:"…"` does not run into the next property's value.
- `additional_patterns` holds the format-specific rules: `jwt`, `private_key` and `aws_keys`. `aws_keys` skips a key ID that directly follows `X-Amz-Credential=` or its URL-encoded form: a presigned S3 URL is made to be handed out, and on one production site such IDs made two of every three report rows.

`ScanerCredentials._findings` applies them. It does not run `credential_pattern` with `IGNORECASE`: with that flag `re` tries every field name at every position, about 1.5 s per MB of script, and the worker's event loop stalls meanwhile. Instead it runs `_assignment`, the same rule built from the same parts with lower-case field names, against a folded copy of the text from `fold_case`. That copy has the same length, so spans and results stay identical. `fold_case` uses `str.lower()`, which folds like `CASE_FOLD` except for the three characters in `LOWER_DIFFERS`; only text containing one of them goes through `CASE_FOLD`. On text with any non-ASCII character, `str.translate` costs about 75 ms per MB and `str.lower()` about 5 ms. The alternation over the field names still costs about 0.17 s per MB. Python's `re` takes the first alternative that matches, so factoring the names into a trie would change labels such as `api_key` for `api_key_secret` unless the trie keeps the list order. `test_benchmark_hits_agree_with_redacted_worker_on_every_page` and `MatcherTests` check this, so build any change to the rule from the shared parts. The page stage reuses it through `ScanerNetworkResources.matcher`, so a rule change affects pages and resources alike. Matches at the same span are merged into a single label such as `api_key + aws_keys`. The worker replaces each value with `[REDACTED]` before returning it.

`tests/measure_rules.py` refuses to run when `RULES` in `tests/credential_corpus.py` differs from the scanner's rule set. Adding or renaming a rule therefore needs a matching corpus update. If the benchmark numbers change, update `reports/website-scan-review/README.md`.

## Invariants the tests enforce

- **Destinations.** Every HTTP session uses `PublicDestinationConnector` from `core/website.py`. It rejects the whole DNS answer if any address is not public unicast.
- **TLS.** Every session, discovery and `coverage` included, verifies certificates and trusts every root in the `requests` CA bundle.
- **Redirects.** Website fetches use `allow_redirects=False` and never read a 3xx body. `fetch_text` follows a redirect itself, and only when the target is inside the scope. An out-of-scope target receives zero requests, and so does any target when no scope is set.
- **Scope.** Scope checks go through `host_in_scope` and `url_in_scope`. A configured entry covers that host and its subdomains only.
- **Domain parsing.** Use the shared `SUFFIXES` from `core/website.py` for registered-domain checks. It is the bundled public suffix list, including private suffixes, and never fetches the list over the network. Do not construct a new `TLDExtract`.
- **No sensitive output.** Logs, console output and CSV never contain matched values, full URLs, paths, queries or target hostnames.
  - Reports reduce URLs to their origin with `report_origin`.
  - Diagnostics log only the provider or stage, the exception type and the HTTP status (`log_discovery_error`, `error_reason`), because exception text can contain a full URL.
  - Tests put a `PRIVATEFIXTUREONLY` marker into the inputs and assert that it never appears in any output.
- **Entry-point names.** Most tests load the CLI with `runpy.run_path("credentialthreat.py")` and read classes such as `ScanerCredentials` and `utils` from that module's globals. Renaming or removing an import in `credentialthreat.py` can break tests that never import it directly.

## Keep in sync

The `DISCOVERY_LIMITS` text in `credentialthreat.py` must match the README's provider rate-limit table and its "checked on" date. `reports/*/README.md` hold the measurements the README links to.
