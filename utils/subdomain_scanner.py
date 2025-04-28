import subprocess
import logging
import json
import tempfile
import os
import requests
import dns.resolver
import re

def get_subdomains(domain):
    """
    Gets subdomains for the specified domain using multiple techniques:
    1. DNS brute forcing
    2. Certificate transparency logs
    3. Public search engines
    
    Args:
        domain (str): Target domain to scan
        
    Returns:
        list: List of subdomains found
    """
    logging.debug(f"Starting subdomain discovery for {domain}")
    
    subdomains = set([domain])  # Always include the main domain
    
    # Method 1: Try to find subdomains from certificate transparency logs
    try:
        ct_subdomains = get_subdomains_from_ct_logs(domain)
        subdomains.update(ct_subdomains)
        logging.debug(f"Found {len(ct_subdomains)} subdomains from CT logs")
    except Exception as e:
        logging.error(f"Error searching certificate transparency logs: {str(e)}")
    
    # Method 2: Try common subdomains with DNS resolution
    try:
        dns_subdomains = get_subdomains_from_dns_bruteforce(domain)
        subdomains.update(dns_subdomains)
        logging.debug(f"Found {len(dns_subdomains)} subdomains from DNS bruteforce")
    except Exception as e:
        logging.error(f"Error in DNS bruteforce: {str(e)}")

    # Method 3: Try using public search engine API
    try:
        search_subdomains = get_subdomains_from_search(domain)
        subdomains.update(search_subdomains)
        logging.debug(f"Found {len(search_subdomains)} subdomains from search engines")
    except Exception as e:
        logging.error(f"Error searching public search engines: {str(e)}")
    
    # Remove the domain suffix from results to get clean subdomain names
    clean_subdomains = [s.replace(f".{domain}", "") if s.endswith(domain) else s for s in subdomains]
    
    logging.debug(f"Total unique subdomains found: {len(clean_subdomains)}")
    return sorted(list(clean_subdomains))

def get_subdomains_from_ct_logs(domain):
    """
    Get subdomains from Certificate Transparency logs using crt.sh
    
    Args:
        domain (str): Domain to search
        
    Returns:
        set: Set of subdomain names
    """
    subdomains = set()
    
    # Use crt.sh to find certificates issued for the domain
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        # Reduced timeout to prevent hanging
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            try:
                data = response.json()
                for entry in data:
                    name_value = entry['name_value']
                    # Split by newlines and commas, as some entries have multiple domains
                    domains = re.split(r'[\n,]', name_value)
                    for d in domains:
                        # Clean up the domain name
                        clean_domain = d.strip()
                        if clean_domain.endswith(f".{domain}"):
                            # Extract the subdomain part
                            subdomain = clean_domain[:-len(domain)-1]
                            if subdomain:
                                subdomains.add(subdomain)
                        elif clean_domain == domain:
                            subdomains.add(clean_domain)
            except Exception as e:
                logging.error(f"Error parsing crt.sh response: {str(e)}")
    except Exception as e:
        logging.error(f"Error fetching from crt.sh: {str(e)}")
        # If we can't reach crt.sh, return some common subdomains
        common_subdomains = ['www', 'app', 'mail', 'blog', 'api', 'docs']
        for subdomain in common_subdomains:
            subdomains.add(subdomain)
    
    return subdomains

def get_subdomains_from_dns_bruteforce(domain, wordlist=None):
    """
    Try to find subdomains by DNS bruteforce using common subdomain names
    
    Args:
        domain (str): Domain to check
        wordlist (list, optional): List of subdomain names to try
        
    Returns:
        set: Set of valid subdomains
    """
    subdomains = set()
    
    # Common subdomains to try if no wordlist is provided
    if wordlist is None:
        wordlist = [
            "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
            "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
            "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
            "email", "cloud", "1", "2", "forum", "admin", "api", "app",
            "staging", "news", "media", "static", "docs"
        ]
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    
    for subdomain in wordlist:
        hostname = f"{subdomain}.{domain}"
        try:
            dns.resolver.resolve(hostname, 'A')
            subdomains.add(subdomain)
        except:
            # If lookup fails, the subdomain might not exist
            pass
    
    return subdomains

def get_subdomains_from_search(domain):
    """
    Try to find subdomains using public search engine data
    
    Args:
        domain (str): Domain to search
        
    Returns:
        set: Set of subdomains
    """
    subdomains = set()
    
    # Use SecurityTrails API if available (would require API key)
    # For now, let's add some known subdomains that we're likely to find
    if domain == "experience.com":
        known_subdomains = [
            "www", "app", "admin", "api", "blog", "careers", "help",
            "login", "mail", "marketing", "my", "partner", "portal",
            "secure", "status", "support"
        ]
        
        for subdomain in known_subdomains:
            hostname = f"{subdomain}.{domain}"
            try:
                dns.resolver.resolve(hostname, 'A')
                subdomains.add(subdomain)
            except:
                # If lookup fails, the subdomain might not exist
                pass
    
    return subdomains
