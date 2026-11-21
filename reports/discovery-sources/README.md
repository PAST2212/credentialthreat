# Keyless discovery sources

Website discovery used two sources, crt.sh and RapidDNS. On 21 November 2026 both failed a large domain in different ways:

- crt.sh answered every query with HTTP 502 for several minutes, even for a domain with no certificates.
- When it answered, crt.sh needed 14.5, 17.0, 27.1 and 64.4 s for **Site C**, a manufacturing group with 6,619 certificate records, and 4.4 s for a repeat within minutes. It ends a query itself with HTTP 504 after 120 s. The discovery session allowed 30 s, so the scanner gave up on one more query after 30 s and scanned 15 hosts instead of 1,525. Commit `fd685a6` gives crt.sh queries their own 150 s timeout.
- RapidDNS states 77,315 records for Site C and serves 100 rows without an account. They contain 15 in-scope hosts.

This report looks for sources that need no account or API key, measures what they add, and records why only one of them was added. Neither the domain nor any hostname is reproduced here.

## Finding candidates

Other recon tools query crt.sh and RapidDNS next to their other sources, so their code lists those sources. A GitHub code search ran for the characteristic request strings:

| Query | Files on GitHub |
| --- | ---: |
| `"crt.sh/?q=" "output=json"` | 15,360 |
| `"crt.sh/?q=%25."` | 7,040 |
| `"crt.sh/?q=%."` | 5,920 |
| `"crt.sh/?q=%25.{"` | 2,652 |
| `"crt.sh/json?q="` | 78 |
| `"rapiddns.io/s/"` | 62 |

The first 300 results of each query gave 1,303 distinct files. Tools with one module per source keep the other sources next to the matching file, so the 9,230 source files in the same directories were read as well. Every URL in these files was reduced to its host, and the hosts were ranked by the number of repositories that reference them. Among the first hundred, the ones that serve subdomain data are:

| Host | Repositories | Status on 21 November 2026 |
| --- | ---: | --- |
| crt.sh | 983 | in use |
| rapiddns.io | 330 | in use |
| web.archive.org | 232 | keyless, returns URLs, see below |
| api.hackertarget.com | 202 | keyless, see below |
| otx.alienvault.com | 192 | passive DNS needs an API key, the URL list does not |
| www.virustotal.com, api.securitytrails.com, api.shodan.io, search.censys.io | 57–179 | API key required |
| urlscan.io | 117 | keyless with quotas, see below |
| api.certspotter.com | 105 | keyless only for evaluation, see below |
| jldc.me, anubisdb.com | 94, 12 | Anubis; jldc.me now redirects and blocks, anubisdb.com answers |
| www.threatcrowd.org, sonar.omnisint.io, api.sublist3r.com, recon.dev, riddler.io, dns.bufferover.run | 25–94 | no longer answer (DNS failure, 404, TLS error) or need an account |
| dnsdumpster.com | 71 | API key required |
| api.threatminer.org | 45 | HTTP 522 |
| index.commoncrawl.org | 31 | HTTP 504 for a wildcard query |
| api.subdomain.center | 21 | keyless, see below |

## Measuring the candidates

Each keyless source was queried once for Site C. crt.sh and RapidDNS together had found 1,539 hosts, and 569 of them resolve to public addresses. For every source, the hosts that crt.sh and RapidDNS did not know were resolved in DNS. The new hosts with public addresses then ran through the scanner's own link stage, with the scanner's TLS trust, timeouts and connection budget.

| Source | Hosts | New | New, public | Start pages read | Links | Resources |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AnubisDB | 3,266 | 1,903 | 840 | 107 | 539 | 1,849 |
| AlienVault OTX, URL list (first page) | 93 | 73 | 66 | 40 | 501 | 786 |
| subdomain.center | 500 | 474 | 90 | 23 | 75 | 230 |
| HackerTarget host search | 50 | 45 | 45 | 20 | 40 | 264 |
| Cert Spotter (first page) | 100 | 99 | 49 | 17 | 64 | 252 |
| urlscan.io search (first page) | 73 | 66 | 45 | 13 | 106 | 139 |
| dnsrepo (HTML page) | 152 | 114 | 50 | 7 | 197 | 279 |
| Hudson Rock | 15 | 9 | 5 | 4 | 82 | 101 |
| Wayback Machine CDX (20,000 URLs) | 12 | 9 | 3 | 2 | 54 | 104 |

For comparison, the link stage read 71 start pages from the 1,539 hosts of crt.sh and RapidDNS. Of their 569 public hosts, 398 accepted no TCP connection: none of 40 sampled hosts connected within 10 s in a sequential check.

The sources barely overlap. Of the 334 new public hosts from all sources except AnubisDB, each source contributes mostly hosts that no other source has.

## Decision

AnubisDB was added as a third provider:

- It more than doubled the start pages that link discovery read, and it contains 1,360 of the 1,525 hosts that crt.sh found (89%). When crt.sh fails, AnubisDB still delivers most of its hosts.
- Its operator describes it as a free API without key or account. The published limit is 60 requests per 10 seconds per source IP, and a domain holds at most 10,000 subdomains. No terms forbid automated use. [Anubis-DB README](https://github.com/jonluca/Anubis-DB#limits)
- It answers with a JSON array of hostnames, `[]` for an unknown domain, and the same list on repeated queries within its five-minute cache.
- Recon tools submit their results to AnubisDB. The scanner only reads from it, so the names it discovers never leave the machine. A test fails on any submission.

The other sources were not added:

- **Cert Spotter** allows unauthenticated queries "for personal or evaluation purposes" and asks production users to sign up. A free account allows 10 queries per hour that include subdomains, and a large domain needs dozens of pages. [Cert Spotter API](https://sslmate.com/help/reference/ct_search_api_v1)
- **subdomain.center** returns 500 random results without a key, so two runs scan different hosts. 68% of its new hosts for Site C did not resolve. Its page announced a temporary outage while it was being checked. [subdomain.center](https://www.subdomain.center/)
- **AlienVault OTX** answers anonymous passive-DNS queries with HTTP 429 and asks for authentication. Its URL list still answers anonymously, but no anonymous limit is published, so the README could not cite one.
- **HackerTarget** returned 50 hosts, all of them public. Its documentation pages answered an automated read with HTTP 403, so no free quota could be confirmed from the operator. Third parties state 50 queries per day.
- **urlscan.io** already serves the `coverage` subcommand and publishes its quotas. It added 13 start pages from the first 100 results.
- **dnsrepo**, **Hudson Rock** and the **Wayback Machine** added fewer than 10 start pages each. dnsrepo is an HTML page without a published limit. Hudson Rock builds its URL list from infostealer data.

HackerTarget, OTX and urlscan.io each found hosts that no other source knew. They are candidates if their limits can be confirmed, or if a user supplies keys.
