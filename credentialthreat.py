import time
import http.cookies
import asyncio
import sys
from colorama import Fore, Style
import multiprocessing
import logging
import math
from queue import Empty
from credentialthreat.core.files import ManageFiles
from credentialthreat.core.subdomainsearch import ScanerSubdomains
from credentialthreat.core.internallinksearch import ScanerInternalLinks
from credentialthreat.core.networksearch import ScanerNetworkResources
from credentialthreat.core.credentialsearch import ScanerCredentials
from credentialthreat.core.utils import SmoothingResults
from credentialthreat.core import utils

logging.basicConfig(level=logging.INFO, format='%(message)s')

if __name__ == '__main__':
    http.cookies._is_legal_key = lambda _: True

    queue = multiprocessing.Queue()

    number_processor = multiprocessing.cpu_count()

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    if 'linux' in sys.platform:
        multiprocessing.set_start_method('fork')

    FG, BT, FR, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Style.RESET_ALL

    domains = ManageFiles().get_domains()

    print('Root Domain(s) to be scanned: ', *domains)

    ManageFiles.create_csv_result_file()

    print(FR + f'\nStart Subdomain Scan' + S)
    subdomains = ScanerSubdomains().get_results(iterables=domains)
    subdomains = list(subdomains)
    print(f'{len(subdomains)} Cumulative Subdomains were found for:', *domains)
    print(f'Example Subdomains: {subdomains[0:20]}')
    print(FG + 'End Subdomain Scan' + S)

    print(FR + "\nStart Internal URL Scan" + S)
    fqdn = subdomains + domains
    internal_links = ScanerInternalLinks().get_results(subdomains=subdomains, domains=domains)
    internal_links_whitelist = internal_links[0]
    internal_links_blacklist = internal_links[1]
    fqdn_normalized = [item for item in fqdn if item not in internal_links_blacklist]
    internal_links_normalized = list(filter(lambda item: item is not None, list(internal_links_whitelist)))
    internal_links_normalized = utils.remove_byte_content_urls(internal_links_normalized)
    print(f'{len(internal_links_normalized)} Internal URLs were found for {len(fqdn_normalized)} Normalized Fully Qualified Domain Names')
    print(f'Example Internal Links: {internal_links_normalized[1:10]}')
    print(FG + "End Internal URL Scan\n" + S)

    host_names = internal_links_normalized + fqdn_normalized
    host_names_normalized = list(filter(lambda item: item is not None and not '', list(set(host_names))))
    print(f'{len(host_names_normalized)} Normalized Host Names were found in total')

    if len(host_names_normalized) > 100000:
        host_names_scaled = host_names_normalized[:100000]
        print('Capped Quantity of Host Names to 100.000 URLs')
    else:
        host_names_scaled = host_names_normalized

    start1 = time.perf_counter()
    print(FR + f"\nStart Multiprocessing Network Resource Scan for {len(host_names_scaled)} Normalized Host Names based on up to {number_processor} detected CPU Cores\n" + S)

    size_chunk_hostnames = math.ceil(len(host_names_scaled) / number_processor)

    chunks_hostnames = utils.chunked_iterable_gen(host_names_scaled, size_chunk_hostnames, cpu_units=number_processor)

    process_pool_hostnames = []

    for chunk in chunks_hostnames:
        process = multiprocessing.Process(target=ScanerNetworkResources().get_results, args=(chunk, domains, queue))
        logging.info(FR + f'\nProcessor Job {chunk[0] + 1} for network url scan is starting for {len(chunk[1])} unique network resources\n' + S)
        process.start()
        process_pool_hostnames.append(process)

    network_files = []

    active_processes_hostnames = len(process_pool_hostnames)

    # # rounding errors due to length of last chunk
    while active_processes_hostnames > 0:
        try:
            length_chunk, result = queue.get(timeout=1.0)
            if isinstance(result, set):
                network_files.append(result)
            active_processes_hostnames -= 1

        except Empty:
            pass

    for process in process_pool_hostnames:
        process.join()

    network_files = SmoothingResults().get_flatten_list(network_files)
    network_files_whitelist = [url_whitelist for url_whitelist in network_files if isinstance(url_whitelist, tuple)]
    network_files_blacklist = list(set([url_blacklist for url_blacklist in network_files if isinstance(url_blacklist, str)]))
    network_files_normalized = utils.deduplicate_script_urls(whitelist=network_files_whitelist, blacklist=network_files_blacklist)
    print(f'\n{len(network_files_normalized)} Normalized Network URLs were found')

    if len(network_files_normalized) > 100000:
        network_files_scaled = network_files_normalized[:100000]
        print('Capped Quantity of Network URLs to 100.000 URLs')
    else:
        network_files_scaled = network_files_normalized

    print(f'Example Network URLs: {[item[1] for item in network_files_scaled][0:8]}')
    end1 = time.perf_counter()
    print(FG + f'End Network Resource Scan: {end1-start1:.2f} Seconds needed' + S)

    start2 = time.perf_counter()
    print(FR + f'\nStart Multiprocessing Credential Leak Candidates Scan for {len(network_files_scaled)} Normalized Network URLs based on up to {number_processor} detected CPU Cores\n' + S)
    size_chunk_leaks = math.ceil(len(network_files_scaled) / number_processor)
    chunks_leaks = utils.chunked_iterable_gen(network_files_scaled, size_chunk_leaks, cpu_units=number_processor)

    process_pool_leaks = []

    for chunk in chunks_leaks:
        process = multiprocessing.Process(target=ScanerCredentials().get_results, args=(chunk, queue))
        logging.info(FR + f'\nProcessor Job {chunk[0] + 1} for credential leak scan is starting for {len(chunk[1])} unique network resources\n' + S)
        process.start()
        process_pool_leaks.append(process)

    leaks = []

    active_processes_leaks = len(process_pool_leaks)

    while active_processes_leaks > 0:
        try:
            length_chunk, result = queue.get(timeout=1)
            if isinstance(result, list):
                leaks.append(result)
            active_processes_leaks -= 1

        except Empty as e:
            pass

    for process in process_pool_leaks:
        process.join()

    leaks = SmoothingResults().get_flatten_list(leaks)
    leaks_normalized = [leak for leak in leaks if isinstance(leak, tuple)]
    end2 = time.perf_counter()
    print(FG + f"End Credential Leak Candidates Scan: {end2 - start2:.2f} Seconds needed\n" + S)
    print(*leaks_normalized, sep='\n')
    print(f'{len(leaks_normalized)} Credential Leak Candidates were found')

    print(FR + '\nStart Writing Results to .csv file in data/output folder' + S)
    ManageFiles.write_csv_result_file(iterables=leaks_normalized)
    print(FG + 'End Writing Results to .csv file in data/output folder\n' + S)
