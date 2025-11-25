"""
SubFindr - Open Source Subdomain Enumeration Tool
Author: ha-2
GitHub: https://github.com/ha-2
License: CC BY-NC 4.0
"""

import asyncio
import aiohttp
import aiodns
import re
from typing import List, Dict, Set, Optional
import logging
from urllib.parse import urljoin, urlparse
import os

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def is_valid_subdomain(hostname: str, domain: str) -> bool:
    """
    Strict validation for subdomain names.
    
    Args:
        hostname (str): The hostname to validate
        domain (str): The target domain
        
    Returns:
        bool: True if hostname is a valid subdomain, False otherwise
    """
    if not hostname or not domain:
        return False
        
    # Convert to lowercase
    hostname = hostname.lower().strip()
    domain = domain.lower().strip()
    
    # Check if hostname ends with the domain
    if not (hostname.endswith("." + domain) or hostname == domain):
        return False
    
    # Reject hostnames containing invalid characters
    invalid_chars = ['@', ' ', '/', '\\', '+', '_', '(', ')']
    if any(char in hostname for char in invalid_chars):
        return False
    
    # Validate using regex - only allow valid DNS characters
    pattern = r"^[a-z0-9.-]+\." + re.escape(domain) + r"$"
    if not re.match(pattern, hostname):
        # Also check for exact domain match
        if hostname != domain:
            return False
    
    # Additional check to ensure it's not an email or other non-hostname
    if '@' in hostname or ' ' in hostname:
        return False
        
    return True

async def resolve_dns(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    """Resolve hostname to IP address"""
    try:
        result = await resolver.query(hostname, 'A')
        return result[0].host
    except Exception as e:
        logger.debug(f"DNS resolution failed for {hostname}: {e}")
        return None

async def check_alive(subdomain: str) -> tuple:
    """Check if subdomain is alive and return status"""
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
        # Try HTTPS first
        try:
            async with session.get(f"https://{subdomain}", timeout=aiohttp.ClientTimeout(total=10)) as response:
                return True, response.status
        except:
            # Try HTTP if HTTPS fails
            try:
                async with session.get(f"http://{subdomain}", timeout=aiohttp.ClientTimeout(total=10)) as response:
                    return True, response.status
            except Exception as e:
                logger.debug(f"Failed to connect to {subdomain}: {e}")
                return False, None

async def bruteforce_scan(domain: str, resolver: aiodns.DNSResolver, semaphore: asyncio.Semaphore) -> Set[str]:
    """Bruteforce subdomain scanning using wordlist"""
    subdomains = set()
    
    try:
        with open("wordlists/subdomains.txt", "r") as f:
            wordlist = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        logger.warning("Wordlist file not found, using default words")
        wordlist = ["www", "api", "dev", "mail", "staging", "admin", "test", 
                   "beta", "cdn", "blog", "ftp", "vpn", "static", "m", "app"]
    
    async def check_word(word):
        async with semaphore:
            subdomain = f"{word}.{domain}"
            ip = await resolve_dns(subdomain, resolver)
            if ip:
                subdomains.add(subdomain)
                logger.info(f"Found subdomain via bruteforce: {subdomain}")
    
    tasks = [check_word(word) for word in wordlist]
    await asyncio.gather(*tasks)
    
    return subdomains

async def ct_logs_scan_crtsh(domain: str) -> Set[str]:
    """Passive scanning using Certificate Transparency logs (crt.sh)"""
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        # Handle multiple names in one entry (separated by newline)
                        names = name.split('\n')
                        for n in names:
                            # Validate subdomain before adding
                            if is_valid_subdomain(n, domain):
                                subdomains.add(n)
                                logger.info(f"Found subdomain via crt.sh: {n}")
                else:
                    logger.warning(f"crt.sh scan failed: HTTP {response.status}")
    except asyncio.TimeoutError as e:
        logger.debug(f"crt.sh scan skipped for this run: Timeout error - {str(e)}")
    except aiohttp.ClientError as e:
        logger.warning(f"crt.sh scan failed: Client error - {str(e)}")
    except Exception as e:
        logger.warning(f"crt.sh scan failed: {str(e)}")
    
    return subdomains

async def ct_logs_scan_certspotter(domain: str) -> Set[str]:
    """Passive scanning using CertSpotter CT logs"""
    subdomains = set()
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        dns_names = entry.get('dns_names', [])
                        for name in dns_names:
                            # Validate subdomain before adding
                            if is_valid_subdomain(name, domain):
                                subdomains.add(name)
                                logger.info(f"Found subdomain via CertSpotter: {name}")
                else:
                    logger.warning(f"CertSpotter scan failed: HTTP {response.status}")
    except asyncio.TimeoutError as e:
        logger.debug(f"CertSpotter scan skipped for this run: Timeout error - {str(e)}")
    except aiohttp.ClientError as e:
        logger.warning(f"CertSpotter scan failed: Client error - {str(e)}")
    except Exception as e:
        logger.warning(f"CertSpotter scan failed: {str(e)}")
    
    return subdomains

async def ct_logs_scan_alienvault(domain: str) -> Set[str]:
    """Passive scanning using AlienVault OTX Passive DNS"""
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    passive_dns = data.get('passive_dns', [])
                    for entry in passive_dns:
                        hostname = entry.get('hostname', '')
                        # Validate subdomain before adding
                        if is_valid_subdomain(hostname, domain):
                            subdomains.add(hostname)
                            logger.info(f"Found subdomain via AlienVault: {hostname}")
                else:
                    logger.warning(f"AlienVault scan failed: HTTP {response.status}")
    except asyncio.TimeoutError as e:
        logger.debug(f"AlienVault scan skipped for this run: Timeout error - {str(e)}")
    except aiohttp.ClientError as e:
        logger.warning(f"AlienVault scan failed: Client error - {str(e)}")
    except Exception as e:
        logger.warning(f"AlienVault scan failed: {str(e)}")
    
    return subdomains

async def ct_logs_scan_certapi(domain: str) -> Set[str]:
    """
    Optional CT source: CertAPI.
    Calls an external HTTP API if configured via CERTAPI_BASE_URL.
    Returns a set of subdomains.
    Does NOT raise on failure; returns empty set on any error.
    """
    subdomains: Set[str] = set()
    base_url = os.getenv("CERTAPI_BASE_URL", "").strip()

    if not base_url:
        # CertAPI not configured, just skip
        return subdomains

    try:
        # Ensure base_url has no trailing slash
        base_url = base_url.rstrip("/")
        url = f"{base_url}/subdomains?domain={domain}"

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    logger.debug(f"CertAPI returned status {resp.status}")
                    return subdomains
                data = await resp.json()

        # Expect a response like:
        # { "domain": "example.com", "subdomains": ["a.example.com", "b.example.com"] }
        # but be tolerant of different keys.
        raw_list = []

        if isinstance(data, dict):
            if "subdomains" in data and isinstance(data["subdomains"], list):
                raw_list = data["subdomains"]
            elif "results" in data and isinstance(data["results"], list):
                raw_list = data["results"]
        elif isinstance(data, list):
            raw_list = data

        for item in raw_list:
            if isinstance(item, str):
                host = item.strip().lower()
                if is_valid_subdomain(host, domain):
                    subdomains.add(host)
                    logger.info(f"Found subdomain via CertAPI: {host}")

    except Exception as e:
        # Fail silently for CertAPI – this is an optional source
        logger.debug(f"CertAPI scan failed: {str(e)}")
        return subdomains

    return subdomains

async def search_engine_scan_duckduckgo(domain: str) -> Set[str]:
    """Search engine enumeration using DuckDuckGo"""
    subdomains = set()
    url = f"https://duckduckgo.com/html/?q=site:{domain}"
    
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=timeout) as response:
                if response.status == 200:
                    text = await response.text()
                    # Extract href values from <a> tags
                    links = re.findall(r'<a[^>]*href=["\']([^"\']*)["\'][^>]*>', text)
                    for link in links:
                        # Parse URL and extract hostname
                        try:
                            parsed = urlparse(link)
                            hostname = parsed.hostname
                            if hostname and is_valid_subdomain(hostname, domain):
                                subdomains.add(hostname)
                                logger.info(f"Found subdomain via DuckDuckGo: {hostname}")
                        except Exception as e:
                            logger.debug(f"Failed to parse link {link}: {e}")
                else:
                    logger.warning(f"DuckDuckGo scan failed: HTTP {response.status}")
    except asyncio.TimeoutError as e:
        logger.debug(f"DuckDuckGo scan skipped for this run: Timeout error - {str(e)}")
    except aiohttp.ClientError as e:
        logger.warning(f"DuckDuckGo scan failed: Client error - {str(e)}")
    except Exception as e:
        logger.warning(f"DuckDuckGo scan failed: {str(e)}")
    
    return subdomains

async def dns_record_scan(domain: str, resolver: aiodns.DNSResolver) -> Set[str]:
    """DNS record enumeration (MX, TXT, NS, SOA, CNAME)"""
    subdomains = set()
    
    try:
        # MX records
        try:
            mx_records = await resolver.query(domain, 'MX', timeout=10)
            for record in mx_records:
                mx_host = record.host
                # Validate subdomain before adding
                if is_valid_subdomain(mx_host, domain):
                    subdomains.add(mx_host)
                    logger.info(f"Found subdomain via MX record: {mx_host}")
        except Exception as e:
            logger.debug(f"MX record query failed: {e}")
        
        # NS records
        try:
            ns_records = await resolver.query(domain, 'NS', timeout=10)
            for record in ns_records:
                ns_host = record.host
                # Validate subdomain before adding
                if is_valid_subdomain(ns_host, domain):
                    subdomains.add(ns_host)
                    logger.info(f"Found subdomain via NS record: {ns_host}")
        except Exception as e:
            logger.debug(f"NS record query failed: {e}")
        
        # SOA record
        try:
            soa_record = await resolver.query(domain, 'SOA', timeout=10)
            soa_host = soa_record[0].mname
            # Validate subdomain before adding
            if is_valid_subdomain(soa_host, domain):
                subdomains.add(soa_host)
                logger.info(f"Found subdomain via SOA record: {soa_host}")
        except Exception as e:
            logger.debug(f"SOA record query failed: {e}")
        
        # TXT records (SPF references)
        try:
            txt_records = await resolver.query(domain, 'TXT', timeout=10)
            for record in txt_records:
                txt_data = record.text if hasattr(record, 'text') else str(record)
                # Look for SPF includes
                spf_includes = re.findall(r'include:([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')', txt_data)
                for include in spf_includes:
                    # Validate subdomain before adding
                    if is_valid_subdomain(include, domain):
                        subdomains.add(include)
                        logger.info(f"Found subdomain via TXT/SPF record: {include}")
        except Exception as e:
            logger.debug(f"TXT record query failed: {e}")
            
    except Exception as e:
        logger.error(f"DNS record scan failed: {e}")
    
    return subdomains

async def js_file_scan(domain: str) -> Set[str]:
    """JS file enumeration to find subdomains"""
    subdomains = set()
    
    # Try both HTTP and HTTPS
    urls_to_try = [f"https://{domain}", f"http://{domain}"]
    
    html_content = None
    for url in urls_to_try:
        try:
            timeout = aiohttp.ClientTimeout(total=20)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, timeout=timeout) as response:
                    if response.status == 200:
                        html_content = await response.text()
                        break
                    else:
                        logger.warning(f"Failed to fetch {url}: HTTP {response.status}")
        except asyncio.TimeoutError as e:
            logger.debug(f"Failed to fetch {url}: Timeout error - {str(e)}")
        except aiohttp.ClientError as e:
            logger.warning(f"Failed to fetch {url}: Client error - {str(e)}")
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {str(e)}")
    
    if not html_content:
        return subdomains
    
    # Extract script tags
    script_urls = re.findall(r'<script[^>]*src=["\']([^"\']*)["\']', html_content)
    
    # Filter out data URLs (data:application/x-javascript; charset=utf-8;base64,...)
    filtered_script_urls = []
    for script_url in script_urls:
        if not script_url.startswith('data:'):
            filtered_script_urls.append(script_url)
        else:
            logger.info(f"Skipping data URL in script src: {script_url[:50]}...")
    
    # Limit to 5 JS files to avoid overwhelming and add concurrency limit
    filtered_script_urls = filtered_script_urls[:5]
    
    # Process each JS file with concurrency limit
    semaphore = asyncio.Semaphore(3)  # Limit concurrent JS file downloads
    
    async def process_js_file(script_url):
        async with semaphore:
            try:
                # Handle relative URLs
                if script_url.startswith('//'):
                    script_url = 'https:' + script_url
                elif script_url.startswith('/'):
                    script_url = f"https://{domain}{script_url}"
                elif not script_url.startswith('http'):
                    script_url = f"https://{domain}/{script_url}"
                
                timeout = aiohttp.ClientTimeout(total=20)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(script_url, timeout=timeout) as response:
                        if response.status == 200:
                            js_content = await response.text()
                            # Find subdomains in JS content
                            found_subdomains = re.findall(r'([a-zA-Z0-9_-]+\.)+' + re.escape(domain), js_content)
                            for match in found_subdomains:
                                subdomain = match.rstrip('.')
                                # Validate subdomain before adding
                                if is_valid_subdomain(subdomain, domain):
                                    subdomains.add(subdomain)
                                    logger.info(f"Found subdomain via JS scan: {subdomain}")
                        else:
                            logger.warning(f"Failed to process JS file {script_url}: HTTP {response.status}")
            except asyncio.TimeoutError as e:
                logger.debug(f"Failed to process JS file {script_url}: Timeout error - {str(e)}")
            except aiohttp.ClientError as e:
                logger.warning(f"Failed to process JS file {script_url}: Client error - {str(e)}")
            except Exception as e:
                logger.warning(f"Failed to process JS file {script_url}: {str(e)}")
    
    # Process JS files concurrently but with limit
    tasks = [process_js_file(script_url) for script_url in filtered_script_urls]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    return subdomains

async def wayback_machine_scan(domain: str) -> Set[str]:
    """Passive DNS using Wayback Machine"""
    subdomains = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
    
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    # Limit to first 100 entries to avoid overwhelming
                    for entry in data[1:101]:  # Skip header row and limit to 100 entries
                        if len(entry) > 2:
                            url_field = entry[2]  # URL field
                            # Extract hostname from URL
                            parsed = urlparse(url_field)
                            hostname = parsed.hostname
                            if hostname and is_valid_subdomain(hostname, domain):
                                subdomains.add(hostname)
                                logger.info(f"Found subdomain via Wayback Machine: {hostname}")
                else:
                    logger.warning(f"Wayback Machine scan failed: HTTP {response.status}")
    except asyncio.TimeoutError as e:
        logger.debug(f"Wayback Machine scan skipped for this run: Timeout error - {str(e)}")
    except aiohttp.ClientError as e:
        logger.warning(f"Wayback Machine scan failed: Client error - {str(e)}")
    except Exception as e:
        logger.warning(f"Wayback Machine scan failed: {str(e)}")
    
    return subdomains

async def aggressive_scan_anubis(domain: str) -> Set[str]:
    """Aggressive scanning using Anubis (JLDC)"""
    subdomains = set()
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                host = item.strip().lower()
                                if is_valid_subdomain(host, domain):
                                    subdomains.add(host)
                                    logger.info(f"Found subdomain via Anubis: {host}")
                else:
                    logger.debug(f"Anubis scan failed: HTTP {response.status}")
    except Exception as e:
        logger.debug(f"Anubis scan failed: {str(e)}")
    
    return subdomains

async def aggressive_scan_sonar(domain: str) -> Set[str]:
    """Aggressive scanning using Sonar Omnisint"""
    subdomains = set()
    url = f"https://sonar.omnisint.io/subdomains/{domain}"
    
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                host = item.strip().lower()
                                if is_valid_subdomain(host, domain):
                                    subdomains.add(host)
                                    logger.info(f"Found subdomain via Sonar: {host}")
                else:
                    logger.debug(f"Sonar scan failed: HTTP {response.status}")
    except Exception as e:
        logger.debug(f"Sonar scan failed: {str(e)}")
    
    return subdomains

async def aggressive_scan_hackertarget(domain: str) -> Set[str]:
    """Aggressive scanning using HackerTarget hostsearch"""
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    # Check if response contains error
                    if text.startswith("error") or "API count exceeded" in text:
                        logger.debug("HackerTarget scan failed: API limit exceeded or error")
                        return subdomains
                    
                    # Process each line
                    lines = text.strip().split('\n')
                    for line in lines:
                        if ',' in line:
                            parts = line.split(',', 1)
                            host = parts[0].strip().lower()
                            if is_valid_subdomain(host, domain):
                                subdomains.add(host)
                                logger.info(f"Found subdomain via HackerTarget: {host}")
                else:
                    logger.debug(f"HackerTarget scan failed: HTTP {response.status}")
    except Exception as e:
        logger.debug(f"HackerTarget scan failed: {str(e)}")
    
    return subdomains

async def aggressive_scan_rapiddns(domain: str) -> Set[str]:
    """Aggressive scanning using RapidDNS HTML scraping"""
    subdomains = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    
    try:
        timeout = aiohttp.ClientTimeout(total=35)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    # Use regex to find subdomains
                    pattern = r'([a-zA-Z0-9_-]+\.)+' + re.escape(domain)
                    matches = re.findall(pattern, text)
                    for match in matches:
                        host = match.rstrip('.').lower()
                        if is_valid_subdomain(host, domain):
                            subdomains.add(host)
                            logger.info(f"Found subdomain via RapidDNS: {host}")
                else:
                    logger.debug(f"RapidDNS scan failed: HTTP {response.status}")
    except Exception as e:
        logger.debug(f"RapidDNS scan failed: {str(e)}")
    
    return subdomains

async def scan_domain(domain: str, mode: str = "basic") -> List[Dict]:
    """Main scanning function that combines all methods"""
    # Normalize domain
    domain = domain.strip().lower()
    if domain.startswith('http://'):
        domain = domain[7:]
    elif domain.startswith('https://'):
        domain = domain[8:]
    
    # Remove trailing slashes
    domain = domain.rstrip('/')
    
    # Normalize mode
    mode = (mode or "basic").lower()
    if mode not in ("basic", "aggressive"):
        mode = "basic"
    
    logger.info(f"Starting scan for domain: {domain} in {mode} mode")
    
    # Initialize resolver with lower timeout
    resolver = aiodns.DNSResolver(timeout=3)
    dns_semaphore = asyncio.Semaphore(30)  # Limit concurrent DNS requests
    
    # Run all scanning methods concurrently with timeout
    basic_tasks = [
        asyncio.wait_for(bruteforce_scan(domain, resolver, dns_semaphore), timeout=35),
        asyncio.wait_for(ct_logs_scan_crtsh(domain), timeout=45),
        asyncio.wait_for(ct_logs_scan_certspotter(domain), timeout=45),
        asyncio.wait_for(ct_logs_scan_alienvault(domain), timeout=45),
        asyncio.wait_for(ct_logs_scan_certapi(domain), timeout=45),
        asyncio.wait_for(dns_record_scan(domain, resolver), timeout=25),
        asyncio.wait_for(js_file_scan(domain), timeout=35),
        asyncio.wait_for(search_engine_scan_duckduckgo(domain), timeout=25),
        asyncio.wait_for(wayback_machine_scan(domain), timeout=45)
    ]
    
    # Add aggressive mode tasks if mode is aggressive
    if mode == "aggressive":
        aggressive_tasks = [
            asyncio.wait_for(aggressive_scan_anubis(domain), timeout=30),
            asyncio.wait_for(aggressive_scan_sonar(domain), timeout=30),
            asyncio.wait_for(aggressive_scan_hackertarget(domain), timeout=30),
            asyncio.wait_for(aggressive_scan_rapiddns(domain), timeout=35),
        ]
    else:
        aggressive_tasks = []
    
    # Combine all tasks
    tasks = basic_tasks + aggressive_tasks
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Handle exceptions and collect results
    all_results = []
    source_names_basic = ["bruteforce", "crtsh", "certspotter", "alienvault", "certapi", "dns", "js", "duckduckgo", "wayback"]
    source_names_aggressive = ["anubis", "sonar", "hackertarget", "rapiddns"]
    source_names = source_names_basic + source_names_aggressive
    
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.warning(f"{source_names[i]} scan failed: {result}")
            all_results.append(set())
        else:
            all_results.append(result)
    
    # Combine results and deduplicate
    all_subdomains = set()
    subdomain_sources = {}
    
    # Process results from all methods
    for i, subdomain_set in enumerate(all_results):
        source_name = source_names[i]
        for subdomain in subdomain_set:
            # Validate subdomain before processing
            if is_valid_subdomain(subdomain, domain):
                # Normalize subdomain (lowercase, strip trailing dots)
                normalized_subdomain = subdomain.lower().rstrip('.')
                all_subdomains.add(normalized_subdomain)
                if normalized_subdomain not in subdomain_sources:
                    subdomain_sources[normalized_subdomain] = []
                subdomain_sources[normalized_subdomain].append(source_name)
    
    logger.info(f"Total unique subdomains found: {len(all_subdomains)}")
    
    # Run alive checks and gather detailed info with concurrency limit
    results = []
    
    async def process_subdomain(subdomain):
        ip = await resolve_dns(subdomain, resolver)
        is_alive, http_status = await check_alive(subdomain) if ip else (False, None)
        
        return {
            "host": subdomain,
            "ip": ip,
            "is_alive": is_alive,
            "http_status": http_status,
            "sources": subdomain_sources.get(subdomain, [])
        }
    
    # Process subdomains concurrently but with limit
    alive_semaphore = asyncio.Semaphore(20)  # Limit concurrent alive checks
    
    async def process_subdomain_with_semaphore(subdomain):
        async with alive_semaphore:
            return await process_subdomain(subdomain)
    
    # Process subdomains concurrently but with limit
    process_tasks = [process_subdomain_with_semaphore(subdomain) for subdomain in all_subdomains]
    results = await asyncio.gather(*process_tasks, return_exceptions=True)
    
    # Filter out exceptions
    filtered_results = []
    for result in results:
        if not isinstance(result, Exception):
            filtered_results.append(result)
    
    return filtered_results
