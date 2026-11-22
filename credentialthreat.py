import time
import http.cookies
import multiprocessing
import logging
import asyncio
import argparse
import sys
from collections import Counter
from functools import partial
from colorama import Fore, Style
from credentialthreat.core.files import ManageFiles
from credentialthreat.core.coverage import PROVIDERS, run_coverage
from credentialthreat.core.subdomainsearch import scan_subdomain_report
from credentialthreat.core.discovery import combined_values, log_query_summary
from credentialthreat.core.internallinksearch import ScanerInternalLinks
from credentialthreat.core.networksearch import ScanerNetworkResources
from credentialthreat.core.credentialsearch import ScanerCredentials
from credentialthreat.core import utils
from credentialthreat.core.utils import UrlPrioritizer
from credentialthreat.core.interrupt_handler import GracefulKiller, ScanInterrupted, create_pool
from credentialthreat.core.website import SUFFIXES, canonical_url, dns_name, host_in_scope, is_binary_url, url_in_scope


logging.basicConfig(level=logging.INFO, format='%(message)s')

DISCOVERY_LIMITS = (
    "Published request limits for website discovery\n"
    "  crt.sh HTTPS (per IP, published 2023-06-09): 5/minute, hour unknown, day unknown\n"
    "  RapidDNS web search (per public IP): 30/minute, hour unknown, day unknown\n"
    "  AnubisDB API (per source IP): 360/minute (60 per 10 seconds), hour unknown, day unknown\n"
    "  AlienVault OTX URL list (without API key): minute unknown, hour unknown, day unknown; "
    "at most 4 requests per domain"
)


def process_chunks_for_credentialsearch(arg):
    """Function that runs in each process"""
    network_files_chunk, domains, host_connections = arg
    # Run async code in a new event loop
    return asyncio.run(ScanerCredentials(scope=domains, host_connections=host_connections).get_results(network_files_chunk))


def process_chunks_for_networksearch(arg):
    """Function that runs in each process"""
    try:
        networkpoints, domains_input, tld_extract, host_connections = arg
        # Run async code in a new event loop
        scanner = ScanerNetworkResources(scope=domains_input, host_connections=host_connections)
        return asyncio.run(scanner.get_results(networkpoints, domains_input, tld_extract))
    except (KeyboardInterrupt, SystemExit) as error:
        # A BaseException would kill the worker without resolving its pool result.
        raise RuntimeError("Network worker interrupted") from error


def process_chunks_for_internallinks(arg):
    """Function that runs in each process"""
    fqdns, tld_extract, domains, host_connections = arg
    # Run async code in a new event loop
    return asyncio.run(ScanerInternalLinks(scope=domains, host_connections=host_connections).get_results(fqdns, tld_extract))


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Find leaked credentials and sensitive data.",
        epilog=DISCOVERY_LIMITS,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('-l', '--limit', type=int, default=100000, help='Maximum number of pages to scan, and separately of other resources such as scripts (default: 100000)')
    modes = parser.add_subparsers(dest="command")
    coverage = modes.add_parser("coverage", help="Report passive counts for exact domain names")
    coverage.add_argument("domains", nargs="+", metavar="DOMAIN", type=coverage_domain)
    coverage.add_argument("--samples", type=int, default=1, help="Queries per domain and source in this UTC hour")
    coverage.add_argument("--source", choices=[provider.NAME for provider in PROVIDERS],
                          help="Query a single coverage provider (default: both)")
    args = parser.parse_args()
    if args.command == "coverage" and args.samples < 1:
        coverage.error("--samples must be positive")
    return args


def coverage_domain(value):
    host = dns_name(value)
    if not host or not SUFFIXES(host).registered_domain:
        raise argparse.ArgumentTypeError("expected a DNS hostname with a registered domain")
    return host


def main():
    try:
        with GracefulKiller().handle_signals() as killer:
            return _run_scan(killer)
    except ScanInterrupted as interruption:
        logging.info("Scan cancelled by %s", interruption)
        return 1


def _log_outcomes(stage: str, outcomes: Counter) -> None:
    """One line per stage: URLs read, error pages read, and why the others were skipped (WARNING unless all were ok)."""
    read = outcomes["ok"] + outcomes["truncated"]
    errors = {key.removesuffix(" read"): count for key, count in outcomes.items() if key.endswith(" read") and count}
    skipped = {key: count for key, count in outcomes.items()
               if key not in ("ok", "truncated") and not key.endswith(" read") and count}
    error_detail = ", ".join(f"{key}={count}" for key, count in sorted(errors.items()))
    detail = ", ".join(f"{key}={count}" for key, count in sorted(skipped.items()))
    logging.log(logging.WARNING if skipped or errors else logging.INFO, "%s requests: ok=%d%s%s, skipped=%d%s",
                stage, read, f" (truncated={outcomes['truncated']})" if outcomes["truncated"] else "",
                f", error status={sum(errors.values())} ({error_detail})" if errors else "",
                sum(skipped.values()), f" ({detail})" if detail else "")


IMPORT_ROUNDS = 5  # rounds of imported modules after the first credential round


def _next_imports(imported, requested: set, domains, budget: int) -> tuple[list[tuple[str, str]], int]:
    """In-scope modules not requested yet, capped at `budget` by priority, and how many the cap left out."""
    new = {}
    for origin, url in imported:
        if url not in requested and url not in new and url_in_scope(origin, domains) and url_in_scope(url, domains):
            new[url] = origin
    selected = [(origin, url) for url, origin in sorted(new.items())]
    budget = max(0, budget)
    if len(selected) <= budget:
        return selected, 0
    # Like the first round, the limit keeps the URL patterns most likely to expose credentials.
    kept = UrlPrioritizer().prioritize_urls(urls=selected, limit=budget, scope=domains) if budget else []
    return kept, len(selected) - len(kept)


def _write_scan_report(leaks, status, partial_discovery=False):
    candidates = sum(len(matches) for _, _, matches in leaks)
    logging.info("Unverified credential matches: %d (affected resources: %d)", candidates, len(leaks))
    logging.info(Fore.RED + '\nStart Writing Results to .csv file in data/output folder' + Style.RESET_ALL)
    ManageFiles.write_csv_result_file(iterables=leaks)
    print(Fore.GREEN + 'End Writing Results to .csv file in data/output folder\n' + Style.RESET_ALL)
    if status:
        logging.warning("Report written with incomplete discovery")
    if partial_discovery:
        # Not a failure (the exit code stays), but the report covers fewer hosts than the providers know.
        logging.warning("Report written with partial discovery: a provider returned only part of its records")
    return status


def _run_scan(killer):
    status = 0

    FG, FY, S = Fore.GREEN, Fore.YELLOW, Style.RESET_ALL

    try:
        args = parse_arguments()
        if args.command == "coverage":
            return asyncio.run(run_coverage(args.domains, args.samples, args.source))
        domains = ManageFiles().get_domains()
        if not domains:
            logging.error("No domains configured in credentialthreat/data/input/domains.txt")
            return 2

        # Get the limit from arguments
        url_limit = args.limit
        print('\nURL Limit: ', FG + str(url_limit) + S)
        # Windows can defer SIGTERM for the duration of a blocking sleep.
        for _ in range(40):
            time.sleep(0.1)

        num_processes = utils.get_workers()
        # The workers share one connection budget per host, so the load on a host does not grow with the CPU count.
        host_connections = utils.host_connections_per_worker(num_processes)

        utils.configure_platform_settings()

        # called directly inside the if __name__ == "__main__": block, because that block is specially recognized as the entry point for the parent process.
        # Calling freeze_support() inside a function may not work as expected, because the frozen child process might not reach that function before it needs to initialize.
        multiprocessing.freeze_support()

        http.cookies._is_legal_key = lambda _: True

        logging.info("Configured domains: %d", len(domains))

        ManageFiles.create_csv_result_file()
        try:
            logging.info(DISCOVERY_LIMITS)
            report = scan_subdomain_report(domains=domains)
            if log_query_summary(report):
                status = 1
            partial_discovery = any(result.partial for result in report)
            subdomains = [host for host in combined_values(r for r in report if r.kind == "hosts")
                          if host_in_scope(host, domains)]
            logging.info("Discovered subdomains in scope: %d", len(subdomains))
            # URL sources name pages that no start page may link to; the page stage scans them like linked pages.
            source_pages = sorted({url for url in map(canonical_url, combined_values(r for r in report if r.kind == "urls"))
                                   if url and url_in_scope(url, domains) and not is_binary_url(url)})
            logging.info("Page URLs from URL sources: %d", len(source_pages))
            logging.info(FG + 'End Subdomain Scan' + S)

        except Exception as e:
            logging.error("Error during subdomain scanning (%s)", type(e).__name__)
            return 1

        fqdn = list(dict.fromkeys(host for host in map(dns_name, subdomains + domains) if host))
        process_chunks = [(chunk, SUFFIXES, domains, host_connections) for chunk in utils.plan_chunks(fqdn, num_processes)]
        total_chunks = len(process_chunks)

        worker = partial(process_chunks_for_internallinks)

        internal_links: set[str] = set()
        start_resources = []  # resources the start pages reference
        link_pages: set[str] = set()  # start pages the link stage requested; the page stage skips them
        leaks = []  # candidates in the page texts, matched by the link and page workers
        link_outcomes: Counter = Counter()
        completed_chunks = 0

        logging.info(FY + f"\nStarting Internal URL Scan: "
                          f"\n├── Total Full Qualified Domain Name: {len(fqdn):,}"
                          f"\n├── Total Chunks: {total_chunks}"
                          f"\n└── CPU Cores: {num_processes}\n" + S)
        try:
            with killer.defer_pool_signals(), create_pool(processes=num_processes) as pool:
                for chunk_result in killer.pool_results(pool, worker, process_chunks):
                    internal_urls, resources, pages, page_leaks, outcomes = chunk_result
                    internal_links.update(internal_urls)
                    start_resources.extend(resources)
                    link_pages.update(pages)
                    leaks.extend(page_leaks)
                    link_outcomes.update(outcomes)
                    completed_chunks += 1
                    logging.info(FG + f"Chunk {completed_chunks}/{total_chunks} completed: {len(internal_urls)} Internal URLs found\n" + S)

        except KeyboardInterrupt:
            logging.info("\nInternal URL scan cancelled by user")
            return 1
        except Exception as e:
            logging.error("Error during internal URL scanning (%s)", type(e).__name__)
            return 1
        _log_outcomes("Internal URL scan", link_outcomes)
        internal_links.update(source_pages)

        # Sorted, so that a URL limit keeps the same pages on every run. The link stage already scanned the start pages.
        host_names_normalized = sorted({url for url in map(canonical_url, internal_links)
                                        if url and url not in link_pages and url_in_scope(url, domains)
                                        and not is_binary_url(url)})
        logging.info(f'{len(host_names_normalized)} Internal URLs were found for {len(fqdn)} Fully Qualified Domain Names')
        host_names_scaled = UrlPrioritizer().prioritize_urls(urls=host_names_normalized, limit=url_limit, scope=domains)
        logging.info(FG + "End Internal URL Scan\n" + S)
        if not host_names_scaled and not start_resources:
            return _write_scan_report(leaks, status, partial_discovery)

        network_files_whitelist = list(start_resources)
        scanned_pages: set = set(link_pages)

        start1 = time.perf_counter()
        if host_names_scaled:
            process_chunks = [(chunk, domains, SUFFIXES, host_connections)
                              for chunk in utils.plan_chunks(host_names_scaled, num_processes)]
            total_chunks = len(process_chunks)

            worker = partial(process_chunks_for_networksearch)

            page_outcomes: Counter = Counter()
            completed_chunks = 0

            logging.info(FY + f"\nStarting Network Resource Scan:"
                              f"\n├── Total URLs: {len(host_names_scaled):,}"
                              f"\n├── Total Chunks: {total_chunks}"
                              f"\n└── CPU Cores: {num_processes}\n" + S)
            try:
                with killer.defer_pool_signals(), create_pool(processes=num_processes) as pool:
                    for chunk_result in killer.pool_results(pool, worker, process_chunks):
                        network_f_whitelist, pages, page_leaks, outcomes = chunk_result
                        network_files_whitelist.extend(network_f_whitelist)
                        scanned_pages.update(pages)
                        leaks.extend(page_leaks)
                        page_outcomes.update(outcomes)
                        completed_chunks += 1
                        logging.info(FG + f"Chunk {completed_chunks}/{total_chunks} completed: {len(network_f_whitelist)} Network URLs found, "
                                          f"{len(page_leaks)} pages with candidates\n" + S)

            except KeyboardInterrupt:
                logging.info("\nNetwork scan cancelled by user")
                return 1
            except Exception as e:
                logging.error("Error during network scanning (%s)", type(e).__name__)
                return 1
            _log_outcomes("Network resource scan", page_outcomes)

        network_files_whitelist = list({obj.script_url: obj for obj in reversed(network_files_whitelist)}.values())
        # The page workers already matched every page they requested, so the credential stage, and the
        # --limit applied to it, covers only the other resources.
        network_files_normalized = utils.deduplicate_script_urls(whitelist=network_files_whitelist, blacklist=scanned_pages)
        network_files_normalized = [(base, resource) for base, resource in network_files_normalized
                                    if url_in_scope(base, domains) and url_in_scope(resource, domains)]
        logging.info(f'\n{len(network_files_normalized)} Normalized Network URLs were found')

        network_files_scaled = UrlPrioritizer().prioritize_urls(urls=network_files_normalized, limit=url_limit, scope=domains)
        end1 = time.perf_counter()
        logging.info(FG + f'End Network Resource Scan: {end1-start1:.2f} Seconds needed' + S)

        if not network_files_scaled:
            return _write_scan_report(leaks, status, partial_discovery)

        worker = partial(process_chunks_for_credentialsearch)

        resource_outcomes: Counter = Counter()
        # Modules that scripts import are fetched in further rounds on the same pool. They count against
        # --limit like every other resource, and no URL is requested twice.
        requested = set(scanned_pages) | {resource for _, resource in network_files_scaled}
        budget = url_limit - len(network_files_scaled)
        pending = network_files_scaled
        rounds = 0

        start2 = time.perf_counter()
        logging.info(FY + f"\nStarting Credential Scan:"
                          f"\n├── Total URLs: {len(network_files_scaled):,}"
                          f"\n├── Total Chunks: {min(len(network_files_scaled), max(1, num_processes))}"
                          f"\n└── CPU Cores: {num_processes}\n" + S)
        try:
            with killer.defer_pool_signals(), create_pool(processes=num_processes) as pool:
                while pending:
                    rounds += 1
                    process_chunks = [(chunk, domains, host_connections) for chunk in utils.plan_chunks(pending, num_processes)]
                    imported = []
                    for completed_chunks, chunk_result in enumerate(killer.pool_results(pool, worker, process_chunks), 1):
                        found_leaks, outcomes, imports = chunk_result
                        leaks.extend(found_leaks)
                        resource_outcomes.update(outcomes)
                        imported.extend(imports)
                        logging.info(FG + f"Chunk {completed_chunks}/{len(process_chunks)} completed: {len(found_leaks)} resources with candidates\n" + S)
                    pending, over_limit = _next_imports(imported, requested, domains, budget)
                    if pending and rounds > IMPORT_ROUNDS:
                        logging.warning("%d imported modules not followed: imports nested deeper than %d rounds",
                                        len(pending), IMPORT_ROUNDS)
                        break
                    if over_limit:
                        logging.warning("%d imported modules skipped by the URL limit", over_limit)
                    budget -= len(pending)
                    requested.update(resource for _, resource in pending)
                    if pending:
                        logging.info(FY + f"\nFollowing imported modules, round {rounds + 1}: {len(pending):,} URLs\n" + S)

        except KeyboardInterrupt:
            logging.info("\nCredential scan cancelled by user")
            return 1
        except Exception as e:
            logging.error("Error during credential scanning (%s)", type(e).__name__)
            return 1
        _log_outcomes("Credential scan", resource_outcomes)

        end2 = time.perf_counter()
        logging.info(FG + f"End Credential Leak Candidates Scan: {end2 - start2:.2f} Seconds needed\n" + S)
        return _write_scan_report(leaks, status, partial_discovery)

    except Exception as e:
        logging.error("Unexpected error in main process (%s)", type(e).__name__)
        return 1


if __name__ == '__main__':
    sys.exit(main())
