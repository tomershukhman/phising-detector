#!/usr/bin/env python3
import csv
import requests
import concurrent.futures
import logging
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import argparse
import tqdm
import os
import multiprocessing
import psutil
import json
import random  # Added missing import
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import re
import collections
import hashlib
import string

# Set up logging
logging.basicConfig(filename='log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def create_session():
    """Create a requests session with connection pooling and retry logic"""
    session = requests.Session()
    
    # Configure retry strategy for better resilience

    
    # Improve connection pool settings - increase connection limits
    adapter = HTTPAdapter(
        pool_connections=100,  # Increase from 50
        pool_maxsize=200,      # Increase from 100
    )
    
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Set default timeout - proper way without overriding request method
    old_request = session.request
    def new_request(method, url, **kwargs):
        if 'timeout' not in kwargs:
            kwargs['timeout'] = 5
        return old_request(method, url, **kwargs)
    
    session.request = new_request
    
    return session

def check_url(url, session, timeout=2):
    """Check if a URL is responsive by sending a HEAD request"""
    try:
        # Skip HEAD request and go straight to GET to avoid double-requests
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'
            
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
            stream=True  # Use streaming to avoid downloading entire content
        )
        
        # Just read a small amount of content to verify connection works
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:  # filter out keep-alive chunks
                break
                
        return True, url, response.status_code
    except requests.exceptions.RequestException as e:
        # Don't log every failure as it floods the logs
        if random.random() < 0.05:  # Only log ~5% of failures
            logging.warning(f"Failed to connect to {url}: {str(e)[:100]}...")
        return False, url, None

def get_optimal_workers():
    """Determine optimal number of workers based on system resources"""
    # For network I/O bound tasks, we can use significantly more workers than CPU cores
    # This is much more efficient for waiting on network responses
    cpu_count = multiprocessing.cpu_count()
    
    # Use 4-8x CPU cores for network I/O bound tasks
    optimal_workers = max(8, cpu_count * 4)
    
    # Cap at 100 workers to avoid overwhelming the network/system
    return min(optimal_workers, 100)

def get_optimal_chunk_size():
    """Determine optimal chunk size based on available memory"""
    # Get available memory in GB
    available_memory_gb = psutil.virtual_memory().available / (1024 ** 3)
    
    # Scale chunk size based on available memory
    if available_memory_gb > 8:
        return 200  # Large memory
    elif available_memory_gb > 4:
        return 100  # Medium memory
    else:
        return 50   # Low memory

def save_progress(processed, output_file, counts_by_status, checkpoint_file='checkpoint.json'):
    """Save progress to allow resuming after interruption"""
    checkpoint = {
        'processed_count': len(processed),
        'output_file': output_file,
        'counts_by_status': counts_by_status,
        'last_processed': list(processed)[-100:] if processed else []  # Save last 100 processed URLs
    }
    with open(checkpoint_file, 'w') as f:
        json.dump(checkpoint, f)

def load_progress(checkpoint_file='checkpoint.json'):
    """Load progress from previous run"""
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, 'r') as f:
            return json.load(f)
    return None

def extract_hostname(url):
    """Extract the hostname from a URL"""
    # Handle URLs that might not have proper scheme
    if not url.startswith(('http://', 'https://')):
        url = f'http://{url}'
    
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Check if it's an IP address
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
            return hostname, True
        
        # Extract the domain and remove 'www.' if present
        parts = hostname.split('.')
        if len(parts) > 1:
            if parts[0] == 'www':
                # Remove www. prefix
                hostname = '.'.join(parts[1:])
                
        return hostname, False
    except:
        return url, False

def is_url_diverse(url, collected_urls_by_status, max_similar_domains=20, max_similar_ips=10, similarity_threshold=0.7):
    """Check if a URL adds diversity to our collection"""
    # Get status from url object (which should be a row dict)
    if isinstance(url, dict):
        status = url.get('status', '0')
        url_str = url['url']
    else:
        # Default to status 0 if we can't determine
        status = '0'
        url_str = url
        
    if not url_str.startswith(('http://', 'https://')):
        url_str = f'http://{url_str}'
    
    # If we don't have many URLs yet, accept all
    if len(collected_urls_by_status.get(status, [])) < 50:
        return True
    
    hostname, is_ip = extract_hostname(url_str)
    
    # Count similar hostnames in our collection
    hostname_counter = collections.Counter()
    for collected_url in collected_urls_by_status.get(status, []):
        collected_hostname, collected_is_ip = extract_hostname(collected_url)
        hostname_counter[collected_hostname] += 1
    
    # Check IP address limits
    if is_ip and hostname_counter[hostname] >= max_similar_ips:
        logging.info(f"Skipping URL {url_str} as we already have {hostname_counter[hostname]} similar IP addresses")
        return False
    
    # Check domain limits
    if not is_ip and hostname_counter[hostname] >= max_similar_domains:
        logging.info(f"Skipping URL {url_str} as we already have {hostname_counter[hostname]} similar domains")
        return False
    
    # Check if this TLD is overrepresented
    if not is_ip:
        tld = hostname.split('.')[-1] if '.' in hostname else hostname
        tld_count = sum(1 for h in hostname_counter if h.endswith(f'.{tld}'))
        
        # Limit the number of URLs from popular TLDs
        popular_tlds = ['com', 'net', 'org', 'io', 'co']
        max_tld_count = 300 if tld in popular_tlds else 150
        
        if tld_count > max_tld_count:
            logging.info(f"Skipping URL {url_str} as we already have {tld_count} URLs with TLD .{tld}")
            return False
    
    return True

def load_existing_urls(output_file):
    """Load existing URLs from the output file to analyze for similarity"""
    collected_urls_by_status = {'0': [], '1': []}
    hostname_counter_by_status = {'0': collections.Counter(), '1': collections.Counter()}
    signature_counter_by_status = {'0': collections.Counter(), '1': collections.Counter()}
    
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        with open(output_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                status = row.get('status', '0')
                url = row['url']
                
                if status in collected_urls_by_status:
                    collected_urls_by_status[status].append(url)
                    
                    hostname, _ = extract_hostname(url)
                    hostname_counter_by_status[status][hostname] += 1
                    
                    # Add URL signature to counter
                    _, sig_hash = compute_url_signature(url)
                    if sig_hash:
                        signature_counter_by_status[status][sig_hash] += 1
    
    # Analyze URL patterns for each status
    for status in ('0', '1'):
        if collected_urls_by_status[status]:
            pattern_analysis = analyze_url_patterns(collected_urls_by_status[status])
            logging.info(f"Pattern analysis for status {status}:")
            logging.info(f"TLD distribution: {pattern_analysis['tld_distribution']}")
            logging.info(f"Common paths: {pattern_analysis['common_paths']}")
            
            # Log if we have overrepresented patterns
            for sig_hash, urls in pattern_analysis['overrepresented_patterns']:
                logging.info(f"Overrepresented pattern {sig_hash} with {len(urls)} URLs")
    
    return collected_urls_by_status, hostname_counter_by_status, signature_counter_by_status

def process_urls(input_file, output_file, max_workers=None, chunk_size=None, target_count=1000,
                max_similar_domains=20, max_similar_ips=10):
    """Process URLs from input CSV and write responsive ones to output CSV"""
    # Auto-determine optimal settings if not provided
    if max_workers is None:
        max_workers = get_optimal_workers()
    if chunk_size is None:
        chunk_size = get_optimal_chunk_size()
    
    logging.info(f"Starting with {max_workers} workers and chunk size of {chunk_size}")
    print(f"Optimized settings: {max_workers} workers, chunk size: {chunk_size}")
    
    # Create a session for connection pooling
    session = create_session()
    
    # Check for checkpoint to resume previous run
    checkpoint = load_progress()
    processed_urls = set()
    counts_by_status = {'0': 0, '1': 0}  # Track counts by status
    
    # Load existing URLs to analyze for diversity
    collected_urls_by_status, hostname_counter_by_status, signature_counter_by_status = load_existing_urls(output_file)
    
    # Update counts_by_status based on collected URLs
    for status, urls in collected_urls_by_status.items():
        counts_by_status[status] = len(urls)
    
    if checkpoint and checkpoint['output_file'] == output_file:
        processed_urls = set(checkpoint['last_processed'])
        if 'counts_by_status' in checkpoint:
            counts_by_status = checkpoint['counts_by_status']
        print(f"Resuming from previous run. Already processed {checkpoint['processed_count']} URLs.")
        print(f"Current counts - Status 0: {counts_by_status.get('0', 0)}, Status 1: {counts_by_status.get('1', 0)}")
        logging.info(f"Resuming from checkpoint with {checkpoint['processed_count']} URLs already processed")
        logging.info(f"Current counts - Status 0: {counts_by_status.get('0', 0)}, Status 1: {counts_by_status.get('1', 0)}")
    
    # Count total lines in the input file for progress bar
    total_lines = sum(1 for _ in open(input_file))
    
    # Calculate how many URLs we need to process to reach our targets
    remaining_urls_needed = max(
        max(0, target_count - counts_by_status.get('0', 0)),
        max(0, target_count - counts_by_status.get('1', 0))
    )
    
    # Estimate how many URLs we need to check to find the required number of responsive ones
    # Based on typical response rate (adjust this based on your data)
    estimated_response_rate = 0.2  # Assume 20% of URLs are responsive
    estimated_urls_to_check = min(total_lines, int(remaining_urls_needed / estimated_response_rate * 1.5))
    
    if estimated_urls_to_check < total_lines:
        print(f"Estimated we need to check ~{estimated_urls_to_check} URLs to reach targets")
    
    responsive_urls = []
    processed_count = 0
    skipped_count = 0
    
    # Create output file directory if it doesn't exist
    os.makedirs(os.path.dirname(os.path.abspath(output_file)) or '.', exist_ok=True)
    
    # Check if output file exists and has header
    output_exists = os.path.exists(output_file) and os.path.getsize(output_file) > 0
    
    # Log hostname distribution for analysis
    for status in ('0', '1'):
        top_hostnames = hostname_counter_by_status[status].most_common(10)
        logging.info(f"Top hostnames for status {status}: {top_hostnames}")
        if top_hostnames:
            print(f"Top hostnames for status {status}:")
            for hostname, count in top_hostnames:
                print(f"  - {hostname}: {count}")
    
    target_reached = False
    
    with open(input_file, 'r') as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames
        
        # Using context managers for output file
        with open(output_file, 'a' if output_exists else 'w', newline='') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            
            # Write header only if creating a new file
            if not output_exists:
                writer.writeheader()
            
            # Process URLs in chunks to avoid memory issues
            with tqdm.tqdm(total=estimated_urls_to_check, desc="Processing URLs") as pbar:
                urls_to_process = []
                urls_checked = 0
                
                for row in reader:
                    # Check if we've reached the target for both statuses
                    if counts_by_status.get('0', 0) >= target_count and counts_by_status.get('1', 0) >= target_count:
                        target_reached = True
                        print(f"\nTarget counts reached! Status 0: {counts_by_status['0']}, Status 1: {counts_by_status['1']}")
                        logging.info(f"Target counts reached! Status 0: {counts_by_status['0']}, Status 1: {counts_by_status['1']}")
                        break
                    
                    # Check if we've reached target for this status
                    status = row.get('status', '')
                    if status in counts_by_status and counts_by_status[status] >= target_count:
                        # Skip this URL if we've already reached the target for its status
                        skipped_count += 1
                        continue
                        
                    url = row['url']
                    
                    # Skip if already processed (from checkpoint)
                    if url in processed_urls:
                        skipped_count += 1
                        continue
                    
                    urls_to_process.append(row)
                    processed_count += 1
                    
                    # Process in chunks
                    if len(urls_to_process) >= chunk_size:
                        batch_size = len(urls_to_process)
                        _process_url_batch(urls_to_process, writer, session, max_workers, responsive_urls, 
                                          pbar, counts_by_status, collected_urls_by_status, 
                                          hostname_counter_by_status, signature_counter_by_status, max_similar_domains, max_similar_ips)
                        
                        # Update urls_checked count instead of updating pbar inside _process_url_batch
                        urls_checked += batch_size
                        
                        # Update progress bar description with current counts and the actual URLs checked
                        pbar.set_description(f"Processed {urls_checked} URLs - Status 0: {counts_by_status.get('0', 0)}/{target_count}, Status 1: {counts_by_status.get('1', 0)}/{target_count}")
                        pbar.update(batch_size)
                        
                        # Update progress bar's total if our estimate was off
                        if urls_checked > pbar.total * 0.5 and (counts_by_status.get('0', 0) < target_count * 0.5 or counts_by_status.get('1', 0) < target_count * 0.5):
                            # We're halfway through but not halfway to our target - adjust the estimate
                            new_total = int(urls_checked * (target_count / max(counts_by_status.get('0', 0), counts_by_status.get('1', 0), 1)))
                            pbar.total = min(new_total, total_lines)
                            pbar.refresh()
                            
                        # Save progress checkpoint every chunk
                        processed_urls.update(row['url'] for row in urls_to_process)
                        save_progress(processed_urls, output_file, counts_by_status)
                        urls_to_process = []
                
                # Process any remaining URLs
                if urls_to_process:
                    batch_size = len(urls_to_process)
                    _process_url_batch(urls_to_process, writer, session, max_workers, responsive_urls, 
                                      pbar, counts_by_status, collected_urls_by_status, 
                                      hostname_counter_by_status, signature_counter_by_status, max_similar_domains, max_similar_ips)
                    urls_checked += batch_size
                    pbar.update(batch_size)
                    pbar.set_description(f"Processed {urls_checked} URLs - Status 0: {counts_by_status.get('0', 0)}/{target_count}, Status 1: {counts_by_status.get('1', 0)}/{target_count}")
    
    print(f"\nProcessed {processed_count} URLs, skipped {skipped_count} URLs")
    
    # Clean up checkpoint file after successful completion or reaching target
    if os.path.exists('checkpoint.json') and (target_reached or (counts_by_status['0'] >= target_count and counts_by_status['1'] >= target_count)):
        os.remove('checkpoint.json')
    
    # Log final hostname distribution
    for status in ('0', '1'):
        top_hostnames = hostname_counter_by_status[status].most_common(20)
        logging.info(f"Final top hostnames for status {status}: {top_hostnames}")
    
    logging.info(f"Finished processing. Found {len(responsive_urls)} responsive URLs. Status 0: {counts_by_status.get('0', 0)}, Status 1: {counts_by_status.get('1', 0)}")
    return responsive_urls, counts_by_status

def _process_url_batch(urls_batch, writer, session, max_workers, responsive_urls, pbar, counts_by_status, 
                      collected_urls_by_status, hostname_counter_by_status, signature_counter_by_status, 
                      max_similar_domains=20, max_similar_ips=10, max_similar_sigs=15):
    """Helper function to process a batch of URLs with threading"""
    # Create a local cache to minimize lookups during batch processing
    local_hostname_cache = {}
    current_domain_counts = {}
    
    # Group URLs by status first to optimize diversity checks
    urls_by_status = {}
    for row in urls_batch:
        status = row.get('status', '0')
        if status not in urls_by_status:
            urls_by_status[status] = []
        urls_by_status[status].append(row)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Process each URL with a maximum timeout
        futures = {
            executor.submit(check_url, row['url'], session): row
            for row in urls_batch
        }
        
        for future in concurrent.futures.as_completed(futures):
            row = futures[future]
            is_responsive, url, status_code = future.result()
            
            # Skip non-responsive URLs immediately
            if not is_responsive:
                continue
                
            status = row.get('status', '0')  # Use existing status or default to '0'
            url_str = row['url']
            
            # Skip if we've already reached the target for this status
            if counts_by_status.get(status, 0) >= 200:  # Using target_count directly
                continue
                
            # Check hostname diversity (caching for efficiency)
            hostname, is_ip = extract_hostname(url_str)
            if hostname in local_hostname_cache:
                # Skip if we already processed too many from this hostname in this batch
                if local_hostname_cache[hostname] >= 2:  # Limit per batch
                    continue
                local_hostname_cache[hostname] += 1
            else:
                local_hostname_cache[hostname] = 1
            
            # Check if we have too many of this hostname already
            existing_count = hostname_counter_by_status[status].get(hostname, 0)
            if is_ip and existing_count >= max_similar_ips:
                continue
                
            if not is_ip and existing_count >= max_similar_domains:
                continue
                
            # Only perform intensive signature checks if we're already collecting many URLs
            if len(collected_urls_by_status.get(status, [])) >= 100:
                # Get URL signature with limited recalculation
                signature, sig_hash = compute_url_signature(url_str)
                
                # Skip if we have too many URLs with this pattern
                if sig_hash and signature_counter_by_status[status].get(sig_hash, 0) >= max_similar_sigs:
                    continue
                    
                # Update signature counter (do this here to avoid duplicating calculation later)
                if sig_hash:
                    signature_counter_by_status[status][sig_hash] = signature_counter_by_status[status].get(sig_hash, 0) + 1
            
            # If we got here, the URL passed all diversity checks
            writer.writerow(row)
            responsive_urls.append(url)
            
            # Count by status
            counts_by_status[status] = counts_by_status.get(status, 0) + 1
            
            # Update collected URLs and hostname counter
            collected_urls_by_status[status].append(url_str)
            hostname_counter_by_status[status][hostname] += 1
            
            # Log successful URL
            if random.random() < 0.05:  # Only log ~5% to reduce log file size
                logging.info(f"Found responsive URL: {url_str}, Status: {status}, Code: {status_code}")

def analyze_url_similarity(url1, url2):
    """Analyze the similarity between two URLs"""
    hostname1 = extract_hostname(url1)
    hostname2 = extract_hostname(url2)
    
    # Use a simple similarity measure based on common substrings
    common_substrings = set(re.findall(r'\w+', hostname1)) & set(re.findall(r'\w+', hostname2))
    similarity_score = len(common_substrings) / max(len(hostname1), len(hostname2))
    
    return similarity_score

def compute_url_signature(url):
    """
    Compute a structural signature of a URL to identify similar patterns
    This helps detect URLs with similar structure but different hostnames/domains
    """
    if not url.startswith(('http://', 'https://')):
        url = f'http://{url}'
        
    try:
        parsed = urlparse(url)
        
        # Extract hostname and path components
        hostname, is_ip = extract_hostname(url)
        path = parsed.path
        
        # Create structural signature based on:
        # 1. Number of subdomains
        # 2. Path depth and structure
        # 3. Query parameter structure (not values)
        
        # Analyze hostname structure
        hostname_parts = hostname.split('.')
        subdomain_count = len(hostname_parts) - 2 if len(hostname_parts) > 2 else 0
        subdomain_count = max(0, subdomain_count)  # Ensure non-negative
        
        # Analyze path structure
        path_parts = [p for p in path.split('/') if p]
        path_depth = len(path_parts)
        
        # Detect numeric patterns in path
        numeric_segments = sum(1 for p in path_parts if p.isdigit())
        
        # Detect random-looking strings (hex, uuid-like, etc.)
        random_segments = sum(1 for p in path_parts if re.search(r'[a-f0-9]{8,}', p.lower()))
        
        # Analyze query parameters
        query_params = list(parse_qs(parsed.query).keys())
        param_count = len(query_params)
        
        # Special cases detection for common hosting patterns
        hosting_patterns = ['appspot', 'netlify', 'herokuapp', 'github.io', 'wcomhost', 
                           'godaddysites', 'wordpress', 'blogspot', 'weebly']
        is_hosting_service = any(pattern in hostname.lower() for pattern in hosting_patterns)
        
        # Create final signature components
        signature = {
            'subdomain_count': subdomain_count,
            'is_ip': is_ip,
            'path_depth': path_depth,
            'numeric_path_segments': numeric_segments,
            'random_path_segments': random_segments,
            'param_count': param_count,
            'is_hosting_service': is_hosting_service,
        }
        
        # Create a simple hash representation of the signature
        sig_str = f"{subdomain_count}_{path_depth}_{numeric_segments}_{random_segments}_{param_count}_{is_hosting_service}"
        signature_hash = hashlib.md5(sig_str.encode()).hexdigest()[:8]
        
        return signature, signature_hash
        
    except Exception as e:
        logging.warning(f"Error computing URL signature for {url}: {e}")
        return {}, ""

def assess_url_diversity(url, collected_urls_by_status, sig_counter_by_status, max_similar_sigs=15):
    """
    Assess if a URL adds diversity to our collection based on structural signatures
    """
    if isinstance(url, dict):
        status = url.get('status', '0')
        url_str = url['url']
    else:
        status = '0'
        url_str = url
    
    # Get URL signature
    signature, sig_hash = compute_url_signature(url_str)
    
    # If we don't have many URLs yet or couldn't compute signature, include it
    if not sig_hash or len(collected_urls_by_status.get(status, [])) < 50:
        return True, signature, sig_hash
    
    # Check if this signature is overrepresented
    if sig_counter_by_status[status][sig_hash] >= max_similar_sigs:
        logging.info(f"Skipping URL {url_str} as we already have {sig_counter_by_status[status][sig_hash]} URLs with similar structure")
        return False, signature, sig_hash
        
    # Check for content type diversity (file extensions)
    file_extension = os.path.splitext(url_str.lower())[1]
    if file_extension:
        extension_count = sum(1 for u in collected_urls_by_status[status] if u.lower().endswith(file_extension))
        if extension_count > 30:  # Limit URLs with same file extension
            logging.info(f"Skipping URL {url_str} as we already have {extension_count} URLs with {file_extension} extension")
            return False, signature, sig_hash
    
    # Check for character pattern distribution
    url_chars = ''.join(re.findall(r'[a-z0-9]', url_str.lower()))
    char_entropy = len(set(url_chars)) / len(url_chars) if url_chars else 0
    
    # Very low entropy URLs often indicate pattern-generated URLs with little variation
    if char_entropy < 0.2 and len(url_str) > 15:
        logging.info(f"Skipping URL {url_str} due to low character entropy (likely pattern-generated)")
        return False, signature, sig_hash
        
    return True, signature, sig_hash

def analyze_url_patterns(urls_list):
    """
    Analyze patterns in a list of URLs to detect repetitive structures
    Returns recommendations for diversity improvements
    """
    signatures = {}
    hostname_tlds = collections.Counter()
    path_patterns = collections.Counter()
    
    for url in urls_list:
        # Extract hostname and TLD
        hostname, is_ip = extract_hostname(url)
        if not is_ip and '.' in hostname:
            tld = hostname.split('.')[-1]
            hostname_tlds[tld] += 1
        
        # Compute signature
        signature, sig_hash = compute_url_signature(url)
        if sig_hash:
            if sig_hash not in signatures:
                signatures[sig_hash] = []
            signatures[sig_hash].append(url)
            
        # Look for common path patterns
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
            path_parts = [p for p in parsed.path.split('/') if p]
            if path_parts:
                path_pattern = '/'.join(['*' if re.search(r'[0-9a-f]{8,}', p.lower()) else p for p in path_parts])
                path_patterns[path_pattern] += 1
        except:
            pass
    
    # Find overrepresented patterns
    overrepresented = [
        (sig_hash, urls) for sig_hash, urls in signatures.items() if len(urls) > 20
    ]
    
    # Find overrepresented TLDs
    tld_distribution = [(tld, count) for tld, count in hostname_tlds.most_common(10)]
    
    # Find overrepresented paths
    common_paths = [(pattern, count) for pattern, count in path_patterns.most_common(10) if count > 5]
    
    return {
        'overrepresented_patterns': overrepresented,
        'tld_distribution': tld_distribution,
        'common_paths': common_paths
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Filter responsive URLs from a CSV file')
    parser.add_argument('--input', default='new_data_urls.csv', help='Input CSV file containing URLs')
    parser.add_argument('--output', default='responsive_urls.csv', help='Output CSV file for responsive URLs')
    parser.add_argument('--workers', type=int, help='Number of worker threads (auto-detected if not specified)')
    parser.add_argument('--chunk', type=int, help='Chunk size for processing (auto-detected if not specified)')
    parser.add_argument('--target', type=int, default=1000, help='Target number of URLs to find for each status (default: 1000)')
    
    args = parser.parse_args()
    
    print(f"Processing URLs from {args.input}...")
    responsive_urls, counts = process_urls(args.input, args.output, args.workers, args.chunk, args.target)
    print(f"Found {len(responsive_urls)} responsive URLs.")
    print(f"Status 0 (phishing): {counts.get('0', 0)}/{args.target}")
    print(f"Status 1 (legitimate): {counts.get('1', 0)}/{args.target}")
    print(f"Results saved to {args.output}")