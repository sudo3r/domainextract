import socket
import ipaddress
import concurrent.futures
import dns.resolver
import dns.reversename
import argparse
import requests
from tqdm import tqdm
import json
import os
from datetime import datetime
from colorama import Fore, Style

VERBOSE = False

def log(message, level="i", verbose=False):
    if verbose and not VERBOSE:
        return

    levels = {
        "i": f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL}",
        "s": f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL}",
        "w": f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL}",
        "e": f"{Fore.LIGHTRED_EX}[-]{Style.RESET_ALL}",
    }
    print(f"{levels.get(level, levels['i'])} {message}")

def get_args():
    parser = argparse.ArgumentParser(description='DNS Domain Extraction Tool')
    parser.add_argument('-c', '--country', type=str, required=False, help='Country code (e.g. US, IR, DE)')
    parser.add_argument('-r', '--range', type=str, required=False, help='Custom IP range (e.g., 192.168.1.0/24)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('-o', '--output', type=str, default=None, help='Output file')
    parser.add_argument('-d', '--dns', type=str, default='8.8.8.8', help='DNS server to use')
    parser.add_argument('-f', '--force-update', action='store_true', help='Force update IP ranges cache')
    parser.add_argument('-b', '--batch-size', type=int, default=1000, help='Number of IPs to process at once')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    if not args.country and not args.range:
        parser.error("Either --country or --range must be specified.")
    return args

def get_ip_ranges_for_country(country_code, force_update=False):
    cache_file = f"ip_ranges_{country_code}.json"
    
    if os.path.exists(cache_file) and not force_update:
        with open(cache_file, 'r') as f:
            log(f"Using cached IP ranges for {country_code}", "s")
            return json.load(f)
    
    log(f"Fetching IP ranges for {country_code} from online sources...", "i")
    
    try:
        url = f"http://www.ipdeny.com/ipblocks/data/countries/{country_code.lower()}.zone"
        response = requests.get(url)
        ip_ranges = response.text.splitlines()
        
        with open(cache_file, 'w') as f:
            json.dump(ip_ranges, f)
        
        log(f"Successfully fetched {len(ip_ranges)} IP ranges for {country_code}", "s")
        return ip_ranges
    except Exception as e:
        log(f"Error fetching IP ranges: {e}", "e")
        return []

def generate_ips_from_ranges(ip_ranges, sample=None):
    for range_str in ip_ranges:
        try:
            network = ipaddress.ip_network(range_str)
            if sample and network.num_addresses > 256:
                hosts = list(network.hosts())
                for host in hosts[:sample]:
                    yield str(host)
            else:
                for host in network.hosts():
                    yield str(host)
        except Exception as e:
            log(f"Invalid network range {range_str}: {e}", "w", verbose=True)

def reverse_dns_lookup(ip, dns_server):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.timeout = 2
        resolver.lifetime = 2
        
        rev_name = dns.reversename.from_address(ip)
        ptr_record = str(resolver.resolve(rev_name, "PTR")[0])[:-1]
        
        try:
            socket.gethostbyname(ptr_record)
            log(f"Found domain: {ptr_record} for IP: {ip}", "s", verbose=True)
            return ptr_record
        except:
            return None
    except Exception as e:
        log(f"DNS lookup failed for {ip}: {e}", "w", verbose=True)
        return None

def scan_ip_batch(ip_batch, dns_server, output_file):
    found = set()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(reverse_dns_lookup, ip, dns_server): ip for ip in ip_batch}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.add(result)
                with open(output_file, 'a') as f:
                    f.write(result + '\n')
    return found

def main():
    global VERBOSE
    args = get_args()
    VERBOSE = args.verbose
    
    threads = args.threads
    output_file = args.output or f"domains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    dns_server = args.dns
    force_update = args.force_update
    batch_size = args.batch_size

    open(output_file, 'w').close()

    if args.country:
        country_code = args.country.upper()
        log(f"Starting scan for country: {country_code}", "i")
        ip_ranges = get_ip_ranges_for_country(country_code, force_update)
        if not ip_ranges:
            log("No IP ranges found. Exiting.", "e")
            return
        log(f"Processing {len(ip_ranges)} IP ranges...", "i")
        ip_generator = generate_ips_from_ranges(ip_ranges, sample=10)
    elif args.range:
        custom_range = args.range
        log(f"Starting scan for custom IP range: {custom_range}", "i")
        ip_ranges = [custom_range]
        ip_generator = generate_ips_from_ranges(ip_ranges, sample=None)

    log(f"Threads: {threads}, Batch size: {batch_size}, DNS: {dns_server}", "i", verbose=True)

    total_found = 0
    current_batch = []
    total_scanned = 0

    with tqdm(desc="Overall Progress") as pbar:
        while True:
            try:
                while len(current_batch) < batch_size:
                    current_batch.append(next(ip_generator))
            except StopIteration:
                pass

            if not current_batch:
                break

            batch_results = scan_ip_batch(current_batch, dns_server, output_file)
            total_found += len(batch_results)

            total_scanned += len(current_batch)
            pbar.update(len(current_batch))
            pbar.set_postfix({'Domains Found': total_found})
            
            current_batch = []

    log(f"Scan completed. Total IPs scanned: {total_scanned}", "s")
    log(f"Total domains found: {total_found}", "s")
    log(f"Results saved to: {output_file}", "s")

if __name__ == '__main__':
    main()