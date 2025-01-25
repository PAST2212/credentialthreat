import time
import http.cookies
import multiprocessing
import logging
import math
import asyncio
import argparse
import multiprocessing as mp
from functools import partial
from colorama import Fore, Style
import tldextract
from credentialthreat.core.files import ManageFiles
from credentialthreat.core.subdomainsearch import scan_subdomains
from credentialthreat.core.internallinksearch import ScanerInternalLinks
from credentialthreat.core.networksearch import ScanerNetworkResources
from credentialthreat.core.credentialsearch import ScanerCredentials
from credentialthreat.core import utils
from credentialthreat.recon.wayback import ScanerWaybackMachine
from credentialthreat.core.utils import UrlPrioritizer


logging.basicConfig(level=logging.INFO, format='%(message)s')


def process_chunks_for_credentialsearch(network_files_chunk: list[tuple[str, str]]):
    """Function that runs in each process"""
    # Run async code in a new event loop
    return asyncio.run(ScanerCredentials().get_results(network_files_chunk))


def process_chunks_for_networksearch(arg):
    """Function that runs in each process"""
    networkpoints, domains_input, tld_extract = arg
    # Run async code in a new event loop
    return asyncio.run(ScanerNetworkResources().get_results(networkpoints, domains_input, tld_extract))


def process_chunks_for_internallinks(arg):
    """Function that runs in each process"""
    fqdns, tld_extract = arg
    # Run async code in a new event loop
    return asyncio.run(ScanerInternalLinks().get_results(fqdns, tld_extract))


def parse_arguments():
    parser = argparse.ArgumentParser(description='Find leaked credentials and sensitive data.')
    parser.add_argument('-l', '--limit', type=int, default=100000, help='Maximum number of URLs to scan (default: 100000)')
    return parser.parse_args()


def main():

    FG, BT, FR, FY, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Fore.YELLOW, Style.RESET_ALL

    args = parse_arguments()

    # Get the limit from arguments
    url_limit = args.limit
    print('\nURL Limit: ', FG + str(url_limit) + S)
    time.sleep(4)

    num_processes = utils.get_workers()

    utils.configure_platform_settings()

    # called directly inside the if __name__ == "__main__": block, because that block is specially recognized as the entry point for the parent process.
    # Calling freeze_support() inside a function may not work as expected, because the frozen child process might not reach that function before it needs to initialize.
    multiprocessing.freeze_support()

    http.cookies._is_legal_key = lambda _: True

    tld_extract_object = tldextract.TLDExtract(include_psl_private_domains=True)
    tld_extract_object('google.com')

    domains = ManageFiles().get_domains()

    logging.info(f'Root Domain(s) to be scanned: {[domain for domain in domains]}')

    ManageFiles.create_csv_result_file()

    subdomains = scan_subdomains(domains=domains)
    subdomains = list(subdomains)
    logging.info(f'{len(subdomains)} Cumulative Subdomains were found for: {[domain for domain in domains]}')
    logging.info(f'Example Subdomains: {subdomains[0:20]}')
    logging.info(FG + 'End Subdomain Scan' + S)
    fqdn = subdomains + domains
    logging.info(FR + f'\nStart Wayback Machine Internal URL Scan' + S)
    urls_wayback = ScanerWaybackMachine().get_results(iterables=domains)
    results_wayback_normalized = [item for item in urls_wayback if tld_extract_object(item).registered_domain in domains]
    logging.info(f'{len(results_wayback_normalized)} Internal URLs were found for {domains} Domain(s) from Wayback Machine')

    size_chunk_fqdn = math.ceil(len(fqdn) / num_processes)
    if size_chunk_fqdn > len(fqdn):
        process_chunks = [(fqdn, tld_extract_object)]
    else:
        process_chunks = [(fqdn[i:i + size_chunk_fqdn], tld_extract_object) for i in range(0, len(fqdn), size_chunk_fqdn)]
    total_chunks = len(process_chunks)

    worker = partial(process_chunks_for_internallinks)

    internal_links_whitelist: list[str] = []
    internal_links_blacklist: set[str] = set()

    completed_chunks = 0

    logging.info(FY + f"\nStarting Internal URL Scan: "
                      f"\n├── Total Full Qualified Domain Name: {len(fqdn):,}"
                      f"\n├── {f"Optimal Chunk Size: {size_chunk_fqdn:,}" if size_chunk_fqdn <= len(fqdn) else f"Optimal Chunk Size: {len(fqdn)}"}"
                      f"\n├── Total Chunks: {total_chunks}"
                      f"\n└── CPU Cores: {num_processes}\n" + S)

    with mp.Pool(processes=num_processes) as pool:
        for chunk_result in pool.imap(worker, process_chunks):
            internal_urls, blacklist = chunk_result
            internal_links_whitelist.extend(internal_urls)
            internal_links_blacklist.update(blacklist)
            completed_chunks += 1
            logging.info(FG + f"Chunk {completed_chunks}/{total_chunks} completed: {len(internal_urls)} Internal URLs found\n" + S)

    internal_links = list(set(results_wayback_normalized + internal_links_whitelist))
    fqdn_normalized = [item for item in fqdn if item not in internal_links_blacklist]
    internal_links_normalized = list(filter(lambda item: item is not None, list(internal_links)))
    internal_links_normalized = utils.remove_byte_content_urls(internal_links_normalized)
    logging.info(f'{len(internal_links_normalized)} Internal URLs were found for {len(fqdn_normalized)} Normalized Fully Qualified Domain Names')

    host_names = internal_links_normalized + fqdn_normalized
    host_names_normalized = list(filter(lambda item: item is not None and not '', list(set(host_names))))
    logging.info(f'{len(host_names_normalized)} Normalized Host Names were found in total')
    host_names_scaled = UrlPrioritizer().prioritize_urls(urls=host_names_normalized, limit=url_limit)
    logging.info(f'Example Normalized Host Names: {host_names_scaled[1:10]}')
    logging.info(FG + "End Internal URL Scan\n" + S)

    optimal_chunk_size = utils.calculate_optimal_chunk_size(sample_urls=host_names_scaled[:100], domains_input=domains, tld_extract=tld_extract_object)
    if optimal_chunk_size > len(host_names_scaled):
        process_chunks = [(host_names_scaled, domains, tld_extract_object)]
    else:
        process_chunks = [(host_names_scaled[i:i + optimal_chunk_size], domains, tld_extract_object) for i in range(0, len(host_names_scaled), optimal_chunk_size)]
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

    with mp.Pool(processes=num_processes) as pool:
        for chunk_result in pool.imap(worker, process_chunks):
            network_f_whitelist, network_f_blacklist = chunk_result
            network_files_whitelist.extend(network_f_whitelist)
            network_files_blacklist.update(network_f_blacklist)
            completed_chunks += 1
            logging.info(FG + f"Chunk {completed_chunks}/{total_chunks} completed: {len(network_f_whitelist)} Network URLs found\n" + S)

    network_files_whitelist = list({obj.script_url: obj for obj in reversed(network_files_whitelist)}.values())
    network_files_normalized = utils.deduplicate_script_urls(whitelist=network_files_whitelist, blacklist=list(network_files_blacklist))
    logging.info(f'\n{len(network_files_normalized)} Normalized Network URLs were found')

    network_files_scaled = UrlPrioritizer().prioritize_urls(urls=network_files_normalized, limit=url_limit)
    logging.info(f'Example Network URLs: {[item[1] for item in network_files_scaled][0:8]}')
    end1 = time.perf_counter()
    logging.info(FG + f'End Network Resource Scan: {end1-start1:.2f} Seconds needed' + S)

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

    with mp.Pool(processes=num_processes) as pool:
        for chunk_result in pool.imap(worker, process_chunks):
            found_leaks = chunk_result
            leaks.extend(found_leaks)
            completed_chunks += 1
            logging.info(FG + f"Chunk {completed_chunks}/{total_chunks} completed: {len(found_leaks)} Credential Candidates found\n" + S)

    end2 = time.perf_counter()
    logging.info(FG + f"End Credential Leak Candidates Scan: {end2 - start2:.2f} Seconds needed\n" + S)
    print(*leaks, sep='\n')
    logging.info(f'{len(leaks)} Credential Leak Candidates were found')

    logging.info(FR + '\nStart Writing Results to .csv file in data/output folder' + S)
    ManageFiles.write_csv_result_file(iterables=leaks)
    print(FG + 'End Writing Results to .csv file in data/output folder\n' + S)


if __name__ == '__main__':
    main()
