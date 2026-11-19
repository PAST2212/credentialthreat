import time
import http.cookies
import multiprocessing
import logging
import math
import asyncio
import argparse
import sys
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
from credentialthreat.core.website import SUFFIXES, dns_name, host_in_scope, url_in_scope


logging.basicConfig(level=logging.INFO, format='%(message)s')

DISCOVERY_LIMITS = (
    "Published request limits for website discovery\n"
    "  crt.sh HTTPS (per IP, published 2023-06-09): 5/minute, hour unknown, day unknown\n"
    "  RapidDNS web search (per public IP): 30/minute, hour unknown, day unknown"
)


def process_chunks_for_credentialsearch(network_files_chunk: list[tuple[str, str]]):
    """Function that runs in each process"""
    # Run async code in a new event loop
    return asyncio.run(ScanerCredentials().get_results(network_files_chunk))


def process_chunks_for_networksearch(arg):
    """Function that runs in each process"""
    try:
        networkpoints, domains_input, tld_extract = arg
        # Run async code in a new event loop
        return asyncio.run(ScanerNetworkResources().get_results(networkpoints, domains_input, tld_extract))
    except (KeyboardInterrupt, SystemExit) as error:
        # A BaseException would kill the worker without resolving its pool result.
        raise RuntimeError("Network worker interrupted") from error


def process_chunks_for_internallinks(arg):
    """Function that runs in each process"""
    fqdns, tld_extract = arg
    # Run async code in a new event loop
    return asyncio.run(ScanerInternalLinks().get_results(fqdns, tld_extract))


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

        fqdn = subdomains + domains
        size_chunk_fqdn = math.ceil(len(fqdn) / num_processes)
        if size_chunk_fqdn > len(fqdn):
            process_chunks = [(fqdn, SUFFIXES)]
        else:
            process_chunks = [(fqdn[i:i + size_chunk_fqdn], SUFFIXES) for i in range(0, len(fqdn), size_chunk_fqdn)]
        total_chunks = len(process_chunks)

        worker = partial(process_chunks_for_internallinks)

        internal_links: set[str] = set()
        internal_links_blacklist: set[str] = set()
        completed_chunks = 0

        logging.info(FY + f"\nStarting Internal URL Scan: "
                          f"\n├── Total Full Qualified Domain Name: {len(fqdn):,}"
                          f"\n├── {f"Optimal Chunk Size: {size_chunk_fqdn:,}" if size_chunk_fqdn <= len(fqdn) else f"Optimal Chunk Size: {len(fqdn)}"}"
                          f"\n├── Total Chunks: {total_chunks}"
                          f"\n└── CPU Cores: {num_processes}\n" + S)
        try:
            with killer.defer_pool_signals(), create_pool(processes=num_processes) as pool:
                for chunk_result in killer.pool_results(pool, worker, process_chunks):
                    internal_urls, blacklist = chunk_result
                    internal_links.update(internal_urls)
                    internal_links_blacklist.update(blacklist)
                    completed_chunks += 1
                    logging.info(FG + f"Chunk {completed_chunks}/{total_chunks} completed: {len(internal_urls)} Internal URLs found\n" + S)

        except KeyboardInterrupt:
            logging.info("\nInternal URL scan cancelled by user")
            return 1
        except Exception as e:
            logging.error("Error during internal URL scanning (%s)", type(e).__name__)
            return 1

        fqdn_normalized = [item for item in fqdn if item not in internal_links_blacklist]
        internal_links_normalized = [url for url in internal_links if url and url_in_scope(url, domains)]
        internal_links_normalized = utils.remove_byte_content_urls(internal_links_normalized)
        logging.info(f'{len(internal_links_normalized)} Internal URLs were found for {len(fqdn_normalized)} Normalized Fully Qualified Domain Names')

        host_names = internal_links_normalized + fqdn_normalized
        host_names_normalized = list(filter(lambda item: item is not None and not '', list(set(host_names))))
        logging.info(f'{len(host_names_normalized)} Normalized Host Names were found in total')
        host_names_scaled = UrlPrioritizer().prioritize_urls(urls=host_names_normalized, limit=url_limit)
        logging.info(FG + "End Internal URL Scan\n" + S)
        if not host_names_scaled:
            return _write_scan_report([], status)

        optimal_chunk_size = utils.calculate_optimal_chunk_size(sample_urls=host_names_scaled[:100], domains_input=domains, tld_extract=SUFFIXES)
        if optimal_chunk_size > len(host_names_scaled):
            process_chunks = [(host_names_scaled, domains, SUFFIXES)]
        else:
            process_chunks = [(host_names_scaled[i:i + optimal_chunk_size], domains, SUFFIXES) for i in range(0, len(host_names_scaled), optimal_chunk_size)]
        total_chunks = len(process_chunks)

        worker = partial(process_chunks_for_networksearch)

        network_files_whitelist = []
        network_files_blacklist: set = set()
        completed_chunks = 0

        start1 = time.perf_counter()
        logging.info(FY + f"\nStarting Network Resource Scan:"
                          f"\n├── Total URLs: {len(host_names_scaled):,}"
                          f"\n├── {f"Optimal Chunk Size: {optimal_chunk_size:,}" if optimal_chunk_size <= len(host_names_scaled) else f"Optimal Chunk Size: {len(host_names_scaled)}"}"
                          f"\n├── Total Chunks: {total_chunks}"
                          f"\n└── CPU Cores: {num_processes}\n" + S)
        try:
            with killer.defer_pool_signals(), create_pool(processes=num_processes) as pool:
                for chunk_result in killer.pool_results(pool, worker, process_chunks):
                    network_f_whitelist, network_f_blacklist = chunk_result
                    network_files_whitelist.extend(network_f_whitelist)
                    network_files_blacklist.update(network_f_blacklist)
                    completed_chunks += 1
                    logging.info(FG + f"Chunk {completed_chunks}/{total_chunks} completed: {len(network_f_whitelist)} Network URLs found\n" + S)

        except KeyboardInterrupt:
            logging.info("\nNetwork scan cancelled by user")
            return 1
        except Exception as e:
            logging.error("Error during network scanning (%s)", type(e).__name__)
            return 1

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
        optimal_chunk_size = utils.calculate_optimal_chunk_size(network_files_scaled[:100])
        if optimal_chunk_size > len(network_files_scaled):
            process_chunks = [network_files_scaled]
        else:
            process_chunks = [network_files_scaled[i:i + optimal_chunk_size] for i in range(0, len(network_files_scaled), optimal_chunk_size)]
        total_chunks = len(process_chunks)

        worker = partial(process_chunks_for_credentialsearch)

        leaks = []
        completed_chunks = 0

        start2 = time.perf_counter()
        logging.info(FY + f"\nStarting Credential Scan:"
                          f"\n├── Total URLs: {len(network_files_scaled):,}"
                          f"\n├── {f"Optimal Chunk Size: {optimal_chunk_size:,}" if optimal_chunk_size <= len(network_files_scaled) else f"Optimal Chunk Size: {len(network_files_scaled)}"}"
                          f"\n├── Total Chunks: {total_chunks}"
                          f"\n└── CPU Cores: {num_processes}\n" + S)
        try:
            with killer.defer_pool_signals(), create_pool(processes=num_processes) as pool:
                for chunk_result in killer.pool_results(pool, worker, process_chunks):
                    found_leaks = chunk_result
                    leaks.extend(found_leaks)
                    completed_chunks += 1
                    logging.info(FG + f"Chunk {completed_chunks}/{total_chunks} completed: {len(found_leaks)} resources with candidates\n" + S)

        except KeyboardInterrupt:
            logging.info("\nCredential scan cancelled by user")
            return 1
        except Exception as e:
            logging.error("Error during credential scanning (%s)", type(e).__name__)
            return 1

        end2 = time.perf_counter()
        logging.info(FG + f"End Credential Leak Candidates Scan: {end2 - start2:.2f} Seconds needed\n" + S)
        return _write_scan_report(leaks, status)

    except Exception as e:
        logging.error("Unexpected error in main process (%s)", type(e).__name__)
        return 1


if __name__ == '__main__':
    sys.exit(main())
