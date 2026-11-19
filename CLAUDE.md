# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

## Commands

Run everything from the repository root. There is no build step.

- Full offline suite: `python -m unittest discover -s tests`
- One file: `python -m unittest discover -s tests -p "test_reports.py"`
- One test by name: `python -m unittest discover -s tests -k test_combined_categories`
- Rule precision/recall benchmark: `python tests/measure_rules.py`

Always go through `discover -s tests`. `test_rule_benchmark.py` imports `credential_corpus` and `measure_rules` as top-level modules, so a dotted `python -m unittest tests.test_x` run fails for it. The shutdown test that needs `fork` is skipped on Windows. `test/` (singular) is ignored legacy scratch and is not part of the suite.

## Architecture

### Website scan pipeline

`_run_scan` in `credentialthreat.py` runs these stages in order:

1. **Discovery** (`core/subdomainsearch.py`) runs in the parent process. It queries crt.sh and RapidDNS for every configured domain and keeps only in-scope hosts.
2. **Internal links** (`core/internallinksearch.py`) fetches each host's home page and collects its `<a href>` links.
3. **Network resources** (`core/networksearch.py`) collects script, link, iframe and other resource URLs, plus inline `import`/`require` targets, from those pages.
4. **Credentials** (`core/credentialsearch.py`) fetches each resource and matches the credential rules against the response text.

Stages 2–4 share one pattern:

- The parent splits the work into chunks and runs them on a `multiprocessing` pool from `interrupt_handler.create_pool`.
- Each chunk goes to a module-level `process_chunks_for_*` function, which calls `asyncio.run` on a scanner class.
- The parent reads results through `GracefulKiller.pool_results`, which converts SIGINT/SIGTERM into `ScanInterrupted`.
- `UrlPrioritizer` in `core/utils.py` caps each stage's input at `--limit` and takes high-priority URL patterns first.
- When a stage has no input, the CLI writes the report straight away and skips the remaining pools. Tests cover this.

The workers have to survive multiprocessing:

- Worker functions must stay module-level and picklable. `configure_platform_settings` uses `spawn` with the Proactor loop on Windows and `fork` on POSIX.
- Workers ignore SIGINT and let the parent handle it.
- A worker must not let a `BaseException` escape: that kills the process without resolving its pool result. Convert it, as `process_chunks_for_networksearch` does.
- The pool size is the physical core count minus one.

`utils.calculate_optimal_chunk_size` makes real requests. It runs a scanner on the first 100 URLs in the parent process to measure memory use per URL. Patch it out in tests.

Exit codes are:

- `0`: the scan completed.
- `1`: any discovery query failed (the report is still written), a stage raised an error, or the scan was interrupted.
- `2`: `domains.txt` contains no domains.

### `coverage` subcommand

`credentialthreat.py coverage DOMAIN...` takes a separate path and never feeds the website scanner. `core/coverage.py` drives the providers in `recon/mnemonic.py` and `recon/urlscan.py`. Each provider is a plain module that exposes `NAME`, `request(domain, until)` and `count(payload, domain)`. The run stops at the end of the current UTC hour. CSV rows go to stdout and quotas and diagnostics to stderr.

### Discovery providers

A website-discovery provider subclasses `SubdomainProvider` in `core/discovery.py` and implements `_scrape_subdomains(session, domain) -> (record_count, hosts)`. Register it in `SUBDOMAIN_SERVICES` in `core/subdomainsearch.py`.

- Raise `UnexpectedFormat` for a response the provider does not recognize, even with HTTP 200. Do not return an empty set for it.
- Call `require_ok` for HTTP status checks.
- `observe` turns each query into a `QueryResult` in one of four states: `hits`, `empty` (a confirmed zero), `filtered` or `error`. The summary log and the exit code depend on those states.

`recon/dnsdumpster.py` and `recon/subdomaincenter.py` are legacy and not registered. Only a diagnostics test still imports them.

### Credential rules

Rules live in `ScanerCredentials.__init__`:

- `credential_pattern` matches a field name, an assignment operator and a quoted value.
- `additional_patterns` holds the format-specific rules: `jwt`, `private_key` and `aws_keys`.

Matches at the same span are merged into a single label such as `api_key + aws_keys`. The worker replaces each value with `[REDACTED]` before returning it.

`tests/measure_rules.py` refuses to run when `RULES` in `tests/credential_corpus.py` differs from the scanner's rule set. Adding or renaming a rule therefore needs a matching corpus update. If the benchmark numbers change, update `reports/website-scan-review/README.md`.

## Invariants the tests enforce

- **Destinations.** Every HTTP session uses `PublicDestinationConnector` from `core/website.py`. It rejects the whole DNS answer if any address is not public unicast.
- **Redirects.** Website fetches use `allow_redirects=False` and skip any 3xx response without reading the body.
- **Scope.** Scope checks go through `host_in_scope` and `url_in_scope`. A configured entry covers that host and its subdomains only.
- **Domain parsing.** Use the shared `SUFFIXES` from `core/website.py` for registered-domain checks. It is the bundled public suffix list, including private suffixes, and never fetches the list over the network. Do not construct a new `TLDExtract`.
- **No sensitive output.** Logs, console output and CSV never contain matched values, full URLs, paths, queries or target hostnames.
  - Reports reduce URLs to their origin with `report_origin`.
  - Diagnostics log only the provider or stage, the exception type and the HTTP status (`log_discovery_error`, `error_reason`), because exception text can contain a full URL.
  - Tests put a `PRIVATEFIXTUREONLY` marker into the inputs and assert that it never appears in any output.
- **Entry-point names.** Most tests load the CLI with `runpy.run_path("credentialthreat.py")` and read classes such as `ScanerCredentials` and `utils` from that module's globals. Renaming or removing an import in `credentialthreat.py` can break tests that never import it directly.

## Keep in sync

The `DISCOVERY_LIMITS` text in `credentialthreat.py` must match the README's provider rate-limit table and its "checked on" date. `reports/*/README.md` hold the measurements the README links to.
