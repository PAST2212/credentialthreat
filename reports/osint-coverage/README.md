# Passive coverage verification

The `coverage` subcommand reports historical A-record counts from mnemonic PassiveDNS and counts of pre-existing public urlscan.io scans for the exact final hostname. The provider modules live in `credentialthreat/recon/`. `credentialthreat/core/coverage.py` handles quotas, pacing, the UTC hour boundary and CSV output. The website scanner runs separately.

## Offline verification

The acceptance test first failed because the CLI rejected the new command. Additional failing regressions reproduced aiohttp silently resending a disconnected GET, using a stale quota minute and failing to resume after a short provider cooldown. The final suite passed 70 of 70 tests on Linux, including the SIGTERM fork regression. Windows passed 69 with the POSIX-only test skipped. Both offline runners recorded zero external network attempts.

## Live verification, 19 November 2026

The requested sample was 50 queries per provider and domain in the 16:00–17:00 UTC quota window. Queries alternated between the three domains. The urlscan search used 20 October 00:00 UTC inclusive to 19 November 00:00 UTC exclusive, subject to anonymous history limits. The first Windows urlscan quota lookup failed TLS validation before any searches. After the CA trust fix, a source-only run completed the urlscan measurements. Certificate and hostname verification remained enabled.

The first data query started at 16:11:05 UTC and the last at 16:26:15 UTC. All 250 data queries received valid replies. Each provider returned the same count on every repeat for the given domain.

| Domain | mnemonic successful | Historical A records | urlscan successful | Public scans | urlscan skipped |
| --- | ---: | ---: | ---: | ---: | ---: |
| example.com | 50 | 21 | 34 | 1,745 | 16 |
| otto.de | 50 | 81 | 33 | 0 | 17 |
| amazon.com | 50 | 22 | 33 | 6 | 17 |

The urlscan quota endpoint reported 100 available searches for the hour before the run and 100 used afterward. Its remaining daily budget dropped from 494 to 394. Skipped searches did not count as observed zeroes. The confirmed zero applies to public scans ending on the exact hostname `otto.de` within the search window. The repeats measure short-term consistency within each provider's public dataset. Completeness and longer-term uptime would require independent evidence.
