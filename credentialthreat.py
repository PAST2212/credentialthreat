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
    "  RapidDNS web search (per public IP): 30/minute, hour unknown, day unknown"
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
    parser.add_argument('-l', '--limit', type=int, default=100000, help='Maximum number of URLs to scan (default: 100000)')
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
    """One line per stage: URLs read, and why the others were skipped (WARNING if any were)."""
    read = outcomes["ok"] + outcomes["truncated"]
    skipped = {key: count for key, count in outcomes.items() if key not in ("ok", "truncated") and count}
    detail = ", ".join(f"{key}={count}" for key, count in sorted(skipped.items()))
    logging.log(logging.WARNING if skipped else logging.INFO, "%s requests: ok=%d%s, skipped=%d%s",
                stage, read, f" (truncated={outcomes['truncated']})" if outcomes["truncated"] else "",
                sum(skipped.values()), f" ({detail})" if detail else "")


def _write_scan_report(leaks, status):
    candidates = sum(len(matches) for _, _, matches in leaks)
    logging.info("Unverified credential matches: %d (affected resources: %d)", candidates, len(leaks))
    logging.info(Fore.RED + '\nStart Writing Results to .csv file in data/output folder' + Style.RESET_ALL)
    ManageFiles.write_csv_result_file(iterables=leaks)
    print(Fore.GREEN + 'End Writing Results to .csv file in data/output folder\n' + Style.RESET_ALL)
    if status:
        logging.warning("Report written with incomplete discovery")
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
            subdomains = [host for host in combined_values(report) if host_in_scope(host, domains)]
            logging.info("Discovered subdomains in scope: %d", len(subdomains))
            logging.info(FG + 'End Subdomain Scan' + S)

        except Exception as e:
            logging.error("Error during subdomain scanning (%s)", type(e).__name__)
            return 1

        fqdn = list(dict.fromkeys(host for host in map(dns_name, subdomains + domains) if host))
        process_chunks = [(chunk, SUFFIXES, domains, host_connections) for chunk in utils.plan_chunks(fqdn, num_processes)]
        total_chunks = len(process_chunks)

        worker = partial(process_chunks_for_internallinks)

        internal_links: set[str] = set()
        link_outcomes: Counter = Counter()
        completed_chunks = 0

        logging.info(FY + f"\nStarting Internal URL Scan: "
                          f"\n├── Total Full Qualified Domain Name: {len(fqdn):,}"
                          f"\n├── Total Chunks: {total_chunks}"
                          f"\n└── CPU Cores: {num_processes}\n" + S)
        try:
            with killer.defer_pool_signals(), create_pool(processes=num_processes) as pool:
                for chunk_result in killer.pool_results(pool, worker, process_chunks):
                    internal_urls, outcomes = chunk_result
                    internal_links.update(internal_urls)
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

        # Sorted, so that a URL limit keeps the same pages on every run.
        host_names_normalized = sorted({url for url in map(canonical_url, internal_links)
                                        if url and url_in_scope(url, domains) and not is_binary_url(url)})
        logging.info(f'{len(host_names_normalized)} Internal URLs were found for {len(fqdn)} Fully Qualified Domain Names')
        host_names_scaled = UrlPrioritizer().prioritize_urls(urls=host_names_normalized, limit=url_limit)
        logging.info(FG + "End Internal URL Scan\n" + S)
        if not host_names_scaled:
            return _write_scan_report([], status)

        process_chunks = [(chunk, domains, SUFFIXES, host_connections)
                          for chunk in utils.plan_chunks(host_names_scaled, num_processes)]
        total_chunks = len(process_chunks)

        worker = partial(process_chunks_for_networksearch)

        network_files_whitelist = []
        network_files_blacklist: set = set()
        page_outcomes: Counter = Counter()
        completed_chunks = 0

        start1 = time.perf_counter()
        logging.info(FY + f"\nStarting Network Resource Scan:"
                          f"\n├── Total URLs: {len(host_names_scaled):,}"
                          f"\n├── Total Chunks: {total_chunks}"
                          f"\n└── CPU Cores: {num_processes}\n" + S)
        try:
            with killer.defer_pool_signals(), create_pool(processes=num_processes) as pool:
                for chunk_result in killer.pool_results(pool, worker, process_chunks):
                    network_f_whitelist, network_f_blacklist, outcomes = chunk_result
                    network_files_whitelist.extend(network_f_whitelist)
                    network_files_blacklist.update(network_f_blacklist)
                    page_outcomes.update(outcomes)
                    completed_chunks += 1
                    logging.info(FG + f"Chunk {completed_chunks}/{total_chunks} completed: {len(network_f_whitelist)} Network URLs found\n" + S)

        except KeyboardInterrupt:
            logging.info("\nNetwork scan cancelled by user")
            return 1
        except Exception as e:
            logging.error("Error during network scanning (%s)", type(e).__name__)
            return 1
        _log_outcomes("Network resource scan", page_outcomes)

        network_files_whitelist = list({obj.script_url: obj for obj in reversed(network_files_whitelist)}.values())
        network_files_normalized = utils.deduplicate_script_urls(whitelist=network_files_whitelist, blacklist=list(network_files_blacklist))
        network_files_normalized = [(base, resource) for base, resource in network_files_normalized
                                    if url_in_scope(base, domains) and url_in_scope(resource, domains)]
        logging.info(f'\n{len(network_files_normalized)} Normalized Network URLs were found')

        network_files_scaled = UrlPrioritizer().prioritize_urls(urls=network_files_normalized, limit=url_limit)
        end1 = time.perf_counter()
        logging.info(FG + f'End Network Resource Scan: {end1-start1:.2f} Seconds needed' + S)

        if not network_files_scaled:
            return _write_scan_report([], status)
        process_chunks = [(chunk, domains, host_connections) for chunk in utils.plan_chunks(network_files_scaled, num_processes)]
        total_chunks = len(process_chunks)

        worker = partial(process_chunks_for_credentialsearch)

        leaks = []
        resource_outcomes: Counter = Counter()
        completed_chunks = 0

        start2 = time.perf_counter()
        logging.info(FY + f"\nStarting Credential Scan:"
                          f"\n├── Total URLs: {len(network_files_scaled):,}"
                          f"\n├── Total Chunks: {total_chunks}"
                          f"\n└── CPU Cores: {num_processes}\n" + S)
        try:
            with killer.defer_pool_signals(), create_pool(processes=num_processes) as pool:
                for chunk_result in killer.pool_results(pool, worker, process_chunks):
                    found_leaks, outcomes = chunk_result
                    leaks.extend(found_leaks)
                    resource_outcomes.update(outcomes)
                    completed_chunks += 1
                    logging.info(FG + f"Chunk {completed_chunks}/{total_chunks} completed: {len(found_leaks)} resources with candidates\n" + S)

        except KeyboardInterrupt:
            logging.info("\nCredential scan cancelled by user")
            return 1
        except Exception as e:
            logging.error("Error during credential scanning (%s)", type(e).__name__)
            return 1
        _log_outcomes("Credential scan", resource_outcomes)

        end2 = time.perf_counter()
        logging.info(FG + f"End Credential Leak Candidates Scan: {end2 - start2:.2f} Seconds needed\n" + S)
        return _write_scan_report(leaks, status)

    except Exception as e:
        logging.error("Unexpected error in main process (%s)", type(e).__name__)
        return 1


if __name__ == '__main__':
    sys.exit(main())
