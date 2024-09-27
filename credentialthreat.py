import time
import http.cookies
import multiprocessing
import logging
import math
from queue import Empty
from tqdm import tqdm
from colorama import Fore, Style
import tldextract
from credentialthreat.core.files import ManageFiles
from credentialthreat.core.subdomainsearch import ScanerSubdomains
from credentialthreat.core.internallinksearch import ScanerInternalLinks
from credentialthreat.core.networksearch import ScanerNetworkResources
from credentialthreat.core.credentialsearch import ScanerCredentials
from credentialthreat.core.utils import SmoothingResults
from credentialthreat.core import utils
from credentialthreat.recon.wayback import ScanerWaybackMachine

logging.basicConfig(level=logging.INFO, format='%(message)s')

if __name__ == '__main__':

    utils.configure_platform_settings()

    # called directly inside the if __name__ == "__main__": block, because that block is specially recognized as the entry point for the parent process.
    # Calling freeze_support() inside a function may not work as expected, because the frozen child process might not reach that function before it needs to initialize.
    multiprocessing.freeze_support()

    http.cookies._is_legal_key = lambda _: True

    result_queue = multiprocessing.Queue()
    progress_queue = multiprocessing.Queue()
    number_processor = multiprocessing.cpu_count()

    tld_extract_object = tldextract.TLDExtract(include_psl_private_domains=True)
    tld_extract_object('google.com')



    FG, BT, FR, S = Fore.GREEN, Style.BRIGHT, Fore.RED, Style.RESET_ALL

    domains = ManageFiles().get_domains()

    print('Root Domain(s) to be scanned: ', *domains)

    ManageFiles.create_csv_result_file()

    logging.info(FR + f'\nStart Subdomain Scan' + S)
    subdomains = ScanerSubdomains().get_results(iterables=domains)
    subdomains = list(subdomains)
    print(f'{len(subdomains)} Cumulative Subdomains were found for:', *domains)
    logging.info(f'Example Subdomains: {subdomains[0:20]}')
    logging.info(FG + 'End Subdomain Scan' + S)

    fqdn = subdomains + domains

    logging.info(FR + f'\nStart Internal URL Scan' + S)
    urls_wayback = ScanerWaybackMachine().get_results(iterables=domains)
    results_wayback_normalized = {item for item in urls_wayback if tld_extract_object(item).registered_domain in domains}
    logging.info(f'{len(results_wayback_normalized)} Internal URLs were found for {domains} Domain(s) from Wayback Machine')

    start1 = time.perf_counter()
    logging.info(FR + f"\nStart Multiprocessing Internal URL Scan for {len(fqdn)} Full Qualified Domain Names on up to {number_processor} detected CPU Cores\n" + S)

    size_chunk_fqdn = math.ceil(len(fqdn) / number_processor)
    chunks_fqdns = utils.chunked_iterable_gen(fqdn, size_chunk_fqdn, cpu_units=number_processor)

    total_urls = len(fqdn)

    process_pool_fqdns = []

    internal_links_whitelist: set[str] = set()
    internal_links_blacklist: set[str] = set()

    with tqdm(total=total_urls, desc="Processing FQDNs") as pbar:
        for i, chunk in enumerate(chunks_fqdns):
            process = multiprocessing.Process(target=ScanerInternalLinks().get_results, args=(chunk, tld_extract_object, result_queue, progress_queue), name=f"ScanProcess-{i+1}")
            logging.info(FR + f'\nProcessor Job {chunk[0] + 1} for Internal URL scan is starting for {len(chunk[1])} Full Qualified Domain Names\n' + S)
            process.start()
            process_pool_fqdns.append(process)

        active_processes_fqdns = len(process_pool_fqdns)

        while active_processes_fqdns > 0:
            try:
                processed = progress_queue.get(timeout=1.0)
                pbar.update(processed)
            except Empty:
                pass

            try:
                length_chunk, result = result_queue.get(timeout=1.0)
                if isinstance(result, tuple):
                    internal_links_whitelist.update(result[0])
                    internal_links_blacklist.update(result[1])
                active_processes_fqdns -= 1
                logging.info(FG + f"\nCompleted processing chunk of {length_chunk} FQDNs. {active_processes_fqdns} processes remaining." + S)

            except Empty:
                pass

    for process in process_pool_fqdns:
        process.join()

    internal_links = results_wayback_normalized | internal_links_whitelist
    fqdn_normalized = [item for item in fqdn if item not in internal_links_blacklist]
    internal_links_normalized = list(filter(lambda item: item is not None, list(internal_links)))
    internal_links_normalized = utils.remove_byte_content_urls(internal_links_normalized)
    logging.info(f'\n{len(internal_links_normalized)} Internal URLs were found for {len(fqdn_normalized)} Normalized Fully Qualified Domain Names')
    logging.info(f'Example Internal Links: {internal_links_normalized[1:10]}')
    logging.info(FG + "End Internal URL Scan\n" + S)

    host_names = internal_links_normalized + fqdn_normalized
    host_names_normalized = list(filter(lambda item: item is not None and not '', list(set(host_names))))
    logging.info(f'{len(host_names_normalized)} Normalized Host Names were found in total')

    if len(host_names_normalized) > 100000:
        host_names_scaled = host_names_normalized[:100000]
        logging.info('Capped Quantity of Host Names to 100.000 URLs')
    else:
        host_names_scaled = host_names_normalized

    start1 = time.perf_counter()
    logging.info(FR + f"\nStart Multiprocessing Network Resource Scan for {len(host_names_scaled)} Normalized Host Names based on up to {number_processor} detected CPU Cores\n" + S)

    size_chunk_hostnames = math.ceil(len(host_names_scaled) / number_processor)

    chunks_hostnames = utils.chunked_iterable_gen(host_names_scaled, size_chunk_hostnames, cpu_units=number_processor)

    process_pool_hostnames = []

    network_files = []

    total_urls = len(host_names_scaled)

    with tqdm(total=total_urls, desc="Processing URLs") as pbar:
        for i, chunk in enumerate(chunks_hostnames):
            process = multiprocessing.Process(target=ScanerNetworkResources().get_results, args=(chunk, domains, tld_extract_object, result_queue, progress_queue), name=f"ScanProcess-{i+1}")
            logging.info(FR + f'\nProcessor Job {chunk[0] + 1} for network URL scan is starting for {len(chunk[1])} unique network resources\n' + S)
            process.start()
            process_pool_hostnames.append(process)

        active_processes_hostnames = len(process_pool_hostnames)

        while active_processes_hostnames > 0:
            try:
                processed = progress_queue.get(timeout=1.0)
                pbar.update(processed)
            except Empty:
                pass

            try:
                length_chunk, result = result_queue.get(timeout=1.0)
                if isinstance(result, set):
                    network_files.append(result)
                active_processes_hostnames -= 1
                logging.info(FG + f"\nCompleted processing chunk of {length_chunk} URLs. {active_processes_hostnames} processes remaining." + S)

            except Empty:
                pass

    for process in process_pool_hostnames:
        process.join()

    network_files = SmoothingResults().get_flatten_list(network_files)
    network_files_whitelist = [url_whitelist for url_whitelist in network_files if isinstance(url_whitelist, tuple)]
    network_files_blacklist = list(set([url_blacklist for url_blacklist in network_files if isinstance(url_blacklist, str)]))
    network_files_normalized = utils.deduplicate_script_urls(whitelist=network_files_whitelist, blacklist=network_files_blacklist)
    logging.info(f'\n{len(network_files_normalized)} Normalized Network URLs were found')

    if len(network_files_normalized) > 100000:
        network_files_scaled = network_files_normalized[:100000]
        logging.info('Capped Quantity of Network URLs to 100.000 URLs')
    else:
        network_files_scaled = network_files_normalized

    logging.info(f'Example Network URLs: {[item[1] for item in network_files_scaled][0:8]}')
    end1 = time.perf_counter()
    logging.info(FG + f'End Network Resource Scan: {end1-start1:.2f} Seconds needed' + S)

    start2 = time.perf_counter()
    logging.info(FR + f'\nStart Multiprocessing Credential Leak Candidates Scan for {len(network_files_scaled)} Normalized Network URLs based on up to {number_processor} detected CPU Cores\n' + S)
    size_chunk_leaks = math.ceil(len(network_files_scaled) / number_processor)

    chunks_leaks = utils.chunked_iterable_gen(network_files_scaled, size_chunk_leaks, cpu_units=number_processor)

    process_pool_leaks = []

    leaks = []

    total_urls = len(network_files_scaled)

    with tqdm(total=total_urls, desc="Processing URLs") as pbar:

        for i, chunk in enumerate(chunks_leaks):
            process = multiprocessing.Process(target=ScanerCredentials().get_results, args=(chunk, result_queue, progress_queue), name=f"ScanProcess-{i+1}")
            logging.info(FR + f'\nProcessor Job {chunk[0] + 1} for credential leak scan is starting for {len(chunk[1])} unique network resources\n' + S)
            process.start()
            process_pool_leaks.append(process)

        active_processes_leaks = len(process_pool_leaks)

        while active_processes_leaks > 0:
            try:
                processed = progress_queue.get(timeout=1.0)
                pbar.update(processed)
            except Empty:
                pass

            try:
                length_chunk, result = result_queue.get(timeout=1)
                if isinstance(result, list):
                    leaks.append(result)
                active_processes_leaks -= 1
                logging.info(FG + f"\nCompleted processing chunk of {length_chunk} URLs. {active_processes_leaks} processes remaining." + S)

            except Empty as e:
                pass

    for process in process_pool_leaks:
        process.join()

    leaks = SmoothingResults().get_flatten_list(leaks)
    leaks_normalized = [leak for leak in leaks if isinstance(leak, tuple)]
    end2 = time.perf_counter()
    logging.info(FG + f"End Credential Leak Candidates Scan: {end2 - start2:.2f} Seconds needed\n" + S)
    print(*leaks_normalized, sep='\n')
    logging.info(f'{len(leaks_normalized)} Credential Leak Candidates were found')

    logging.info(FR + '\nStart Writing Results to .csv file in data/output folder' + S)
    ManageFiles.write_csv_result_file(iterables=leaks_normalized)
    print(FG + 'End Writing Results to .csv file in data/output folder\n' + S)
