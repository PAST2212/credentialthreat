# Website scan review

## How the current scan works

The CLI combines configured domains with in-scope hostnames from crt.sh and RapidDNS. It fetches page links, selects web resources, then examines response text using keyword-and-assignment rules and three existing format-specific rules. The scanner reads HTTP response text without executing JavaScript. A match records a candidate. It cannot establish who owns a value, whether it grants access, or whether a public identifier belongs in client code.

The general rule looks for a named field and a quoted value. Separate rules recognize JWT-shaped text, a private-key block, and an AWS access-key identifier. An identifier alone does not establish access. These independent rules can describe the same text, which matters when counting findings.

## Offline precision and recall

Run `python tests/measure_rules.py` from the checkout. The benchmark scores the matcher on 39 synthetic HTML responses. It bypasses discovery and HTTP. Before measuring, the author labeled 31 rule occurrences by rule, page and exact half-open source span. Of these, 24 simulate findings the owner wants to review and seven represent deliberately published examples. A position labeled for two rules contributes once to each. A duplicate cannot claim a second true positive. Precision is TP / (TP + FP), recall is TP / (TP + FN), and an empty denominator prints `n/a`.

**Owner-review results.** Before and after use the same pages and annotations. FP and FN page names refer to the current matcher. The command also prints their character offsets.

| Rule | TP / FP / FN before → after | Precision before → after | Recall | Remaining FP pages | Remaining FN pages |
| --- | --- | --- | --- | --- | --- |
| Assignment | 8 / 5 / 2 → 8 / 3 / 2 | 61.5% → 72.7% | 80.0% | `assignment-guide`, `public-key-help`, `mixed-config` | `json-config`, `mixed-config` |
| JWT | 4 / 2 / 0 → 4 / 2 / 0 | 66.7% → 66.7% | 100% | `jwt-manual`, `mixed-script` | None |
| Private-key block | 5 / 3 / 0 → 5 / 1 / 0 | 62.5% → 83.3% | 100% | `pem-manual` | None |
| AWS key identifier | 5 / 1 / 0 → 5 / 1 / 0 | 83.3% → 83.3% | 100% | `id-manual` | None |
| All rule occurrences | 22 / 11 / 2 → 22 / 7 / 2 | 66.7% → 75.9% | 91.7% | | |

**Format recognition.** Counting published examples as correctly recognized formats gives 11/0/2 for assignment, 6/0/0 for JWT, 6/0/0 for private-key blocks and 6/0/0 for AWS identifiers (TP/FP/FN after). All four previous format false alarms disappeared. The debug setting triggered two of them (`debug-option`, `mixed-script`). In the other two, PEM opening and closing labels disagreed (`pem-crossed-a`, `pem-crossed-b`). All four cases failed against the redacted worker before the fixes.

The two missed assignments are in JSON configuration. In `mixed-config`, a correctly recognized documentation example and a missed review-worthy value occur at different positions. They count as one FP and one FN for owner review. Some example and review pages have byte-identical HTML, so response text alone cannot distinguish their intended use. The fixtures use inert placeholders and a small selection of field names. These figures describe this fixed corpus only. The corpus file had SHA-256 `057b87194f80afb7262143fd316dbe9c7f02a2565e439908b53614a7277be45a` with LF line endings at both measurements.

Later pages hold no target. Each reproduces a false positive from a production site, and each scored as one until the rule changed:

- `next-property`: the assignment rule ran from `withCredentials` across a comma into the next property's value, until its separator stopped admitting commas.
- `id-presigned-url`: the AWS rule matched the access key ID in the `X-Amz-Credential` parameter of a presigned S3 URL, which is made to be handed out. The rule now skips an ID that directly follows `X-Amz-Credential=` or its URL-encoded form.
- `cors-keyword`: the assignment rule matched the CORS mode `use-credentials` assigned to `withCredentials`. Like `same-origin`, this value is now excluded.

With these pages the corpus file has SHA-256 `474593d09fbdd4ff3c64165166b87483f9e1b2c9dde88cabd36d5597a4278a45` with LF line endings, and every score above is unchanged.

## Verified defects and changes

| Reproduced with synthetic inputs | Current behavior |
| --- | --- |
| Configuring a single subdomain widened the scope to its parent. Similar-looking resource hosts and off-site inline references entered the queue. | The configured DNS name and its descendants define the boundary. The CLI filters provider results and checks resource destinations before sampling and dispatch. Internationalized names use the HTTP client's spelling. |
| All three website fetchers disabled certificate checks, followed redirects, and read redirect bodies. | Each verifies HTTPS certificates and skips 3xx responses. A second loopback server received zero redirected requests. |
| All five scan stages passed a private DNS answer to the socket dialer. On a cold start, suffix parsing also attempted a separate HTTP request. | The shared connector checks the numeric addresses used for each new connection and rejects the entire answer if any address is excluded. The CLI uses the bundled suffix list. |
| Raw values and credential-bearing URLs appeared in worker results, terminal output, CSV cells or error messages. | Workers return categories and origins. The CLI reports counts and records exception types for failed website stages. New CSVs omit userinfo, paths, queries, fragments and values, including when the writer receives older result tuples. |
| All six discovery provider handlers printed the full URL and message from a synthetic HTTP exception. The CLI also printed configured hostnames during successful discovery. | Provider errors report the stage, exception type and available HTTP status. The CLI prints counts for configured domains and in-scope discovery results. |
| Two matches in one resource produced one oversized CSV row and counted as one candidate. A documentation fixture with a public-key label also triggered the matcher. | Each occurrence gets one four-column row. Match and affected-resource counts are separate. All categories are unverified, with a contextual note for labels that can identify public material. |
| One synthetic value matched a field name and a format rule, producing two findings. The same value at two positions produced four. | Exact value spans are grouped within each response. The two fixtures now produce one and two redacted rows respectively, each naming both rules. Partial overlaps and different positions remain separate. |
| Both combinations of mismatched opening and closing quotes produced assignment findings. A plain `app_log_level = "CRITICAL"` also produced a finding. | A quoted assignment must close with its opening delimiter. The generic keyword list no longer treats the log-level setting as evidence. A documentation example labeled `public_key` still illustrates why a match needs review. |

New reports have a separate filename. Historical exports may still contain plaintext. Origin-only reporting means different paths on one host can look identical. The address check excludes internal-only sites, mixed public/private answers and IPv6 transition ranges. OS routing still determines where packets go. Explicit HTTP URLs use an unencrypted connection.

## Research

OWASP identifies tokens, passwords and encryption keys as sensitive logging data. Yelp's design separates detection from the baseline used for auditing. This project omits matched values from its reports entirely. [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude) · [Yelp detect-secrets design](https://github.com/Yelp/detect-secrets/blob/master/docs/design.md)

Yelp treats detections from different plugins as distinct evidence. Here, a row represents one position in the response, so it retains both category names. GitHub tests custom patterns on examples and offers a dry run before they generate alerts. Samsung's CredData uses manually reviewed labels to evaluate detectors. The synthetic cases above measure these specific defects. Overall precision and recall on deployed websites have not been measured. [GitHub custom-pattern testing](https://docs.github.com/en/code-security/how-tos/secure-your-secrets/customize-leak-detection/define-custom-patterns) · [CredData methodology](https://github.com/Samsung/CredData#ground-rules-for-labeling-suspected-credential-information) · [Yelp finding identity](https://github.com/Yelp/detect-secrets/blob/master/docs/design.md#potentialsecret)

Stripe documents public client-side keys and confidential server-side keys. The report preserves an occurrence for owner review and describes the uncertainty. [Stripe key types](https://docs.stripe.com/keys)

The connector uses aiohttp 3.11.10's internal `_resolve_host` hook because it covers DNS results, cache hits and IP literals. When updating aiohttp, run the transport tests against the new version. [Pinned connector source](https://github.com/aio-libs/aiohttp/blob/v3.11.10/aiohttp/connector.py#L908-L947)

In the pinned aiohttp release, formatting a `ClientResponseError` includes both the server message and the request URL. Discovery diagnostics select individual fields from the exception. [Pinned exception source](https://github.com/aio-libs/aiohttp/blob/v3.11.10/aiohttp/client_exceptions.py#L105-L113)

## Verification

The CLI regression intercepted four provider requests before removal and exactly two afterward, one each to crt.sh and RapidDNS. Both adapters classify each query. The CLI flags a partial report with exit code 1 and keeps the other source's results. Offline fixtures cover recognized empty payloads, timeouts, DNS and HTTP errors, unexpected formats, cancellation and results outside the queried domain. A connector-level test distinguishes a blocked private address from a DNS lookup failure before opening a socket.

The matcher regressions first reproduced mixed-quote assignments, log-level false positives and duplicate findings. The CLI integration test runs the real matcher against a synthetic response and checks the terminal count, CSV rows, combined categories and redaction.

After removing the two providers, 56 tests passed on Windows and the POSIX-only fork test skipped. On Linux x86_64 (kernel `6.12.115-0-virt`, Python 3.12.16), all 57 passed in 7.354 seconds. The Linux VM had only loopback, and both test runners recorded zero external network attempts. The fork regression passed and the separate SIGTERM probe observed exit code `-15`. The earlier benchmark runs on both platforms produced identical error locations.
