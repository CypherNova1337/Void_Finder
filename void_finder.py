#!/usr/bin/env python3
#
# Origin Finder - A comprehensive tool to investigate the origin IP of a domain.
# This script uses multiple techniques including DNS, HTTP headers, Shodan, and
# a WHOIS self-check to uncover IPs hidden behind CDNs.
#

import socket
import argparse
import sys
import dns.resolver
import requests
import shodan
from ipwhois import IPWhois
from ipaddress import ip_address as validate_ip

# --- CONFIGURATION ---

# Shodan: An API key is optional. The script will skip the Shodan search if a key
# is not provided. Note that effective use of the 'hostname' filter on Shodan
# generally requires a paid plan.
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY_HERE"

# A list of common subdomains to check. Feel free to expand this list.
SUBDOMAINS_TO_CHECK = [
    "ftp", "cpanel", "webmail", "mail", "dev", "staging", "test", "vpn",
    "portal", "admin", "direct", "direct-connect", "blog", "api", "shop"
]

# --- INVESTIGATION FUNCTIONS ---

def get_a_records(domain):
    """Performs a basic DNS 'A' record lookup for a domain."""
    found_ips = set()
    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        for ip in ip_list:
            found_ips.add(ip)
        print(f"  ✔️  Found A Records for {domain}: {', '.join(ip_list)}")
    except socket.gaierror:
        print(f"  ⚠️  Could not resolve A Records for {domain}")
    return found_ips

def check_http_headers(domain):
    """Connects to the domain and prints response headers."""
    print("\n🔎 [Step 2] Checking HTTP Headers...")
    urls_to_check = [f"http://{domain}", f"https://{domain}"]
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    for url in urls_to_check:
        try:
            response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            print(f"  ✔️  Headers from {url} (Status: {response.status_code}):")
            for key, value in response.headers.items():
                if key.lower() in ['server', 'x-powered-by', 'x-originating-ip', 'x-real-ip']:
                    print(f"    ✨ {key}: {value}")
                else:
                    print(f"    {key}: {value}")
        except requests.exceptions.RequestException:
            print(f"  ⚠️  Could not connect to {url}. Skipping.")

def get_mx_ips(domain):
    """Finds mail (MX) servers and resolves their IP addresses."""
    print("\n🔎 [Step 3] Checking Mail (MX) Records...")
    found_ips = set()
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if not mx_records:
            print("  No MX records found.")
            return found_ips
            
        for record in mx_records:
            mail_server_host = str(record.exchange).rstrip('.')
            print(f"  Found mail server: {mail_server_host}")
            mail_server_ips = get_a_records(mail_server_host)
            found_ips.update(mail_server_ips)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"  ⚠️  No MX records found for {domain}")
    return found_ips

def find_subdomain_ips(domain, subdomains):
    """Checks a list of subdomains to see if they resolve to an IP."""
    print("\n🔎 [Step 4] Scanning for common subdomains...")
    found_ips = set()
    for sub in subdomains:
        full_subdomain = f"{sub}.{domain}"
        sub_ips = get_a_records(full_subdomain)
        found_ips.update(sub_ips)
    return found_ips

def search_shodan(domain, api_key):
    """Searches Shodan for the domain name to find associated IPs."""
    print("\n🔎 [Step 5] Searching Shodan (Optional)...")
    found_ips = set()
    if not api_key or "YOUR_SHODAN_API_KEY_HERE" in api_key:
        print("  ⚠️  Shodan API key not configured. Skipping search.")
        return found_ips
    
    try:
        api = shodan.Shodan(api_key)
        results = api.search(f"hostname:{domain}")
        
        if results.get('total', 0) > 0:
            for result in results.get('matches', []):
                ip = result['ip_str']
                found_ips.add(ip)
                print(f"  ✔️  Found potential IP on Shodan: {ip} (Port: {result['port']}, Org: {result.get('org', 'N/A')})")
        else:
            print("  No results found on Shodan.")
    except shodan.APIError as e:
        print(f"  ❌ Shodan API Error: {e}")
    return found_ips

def check_ip_whois(ip):
    """Performs a WHOIS lookup to find the owner of an IP address."""
    try:
        # Prevent lookup of private IP ranges
        if validate_ip(ip).is_private:
            return "Private IP Address"
        
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        # 'asn_description' is usually the most useful field
        owner = results.get('asn_description', 'N/A')
        return f"Owner: {owner}"
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

def main():
    """Main function to orchestrate the IP finding process."""
    parser = argparse.ArgumentParser(
        description="A tool to find the origin IP address of a website, bypassing CDNs and other proxies.",
        epilog="Use this tool responsibly for educational and security assessment purposes only."
    )
    parser.add_argument("domain", help="The target domain to investigate (e.g., example.com)")
    args = parser.parse_args()
    
    target_domain = args.domain
    print(f"\n--- 🚀 Starting Investigation for: {target_domain} ---")
    
    all_found_ips = set()
    
    # Run all investigation steps
    print("\n🔎 [Step 1] Checking base domain A Records...")
    base_ips = get_a_records(target_domain)
    all_found_ips.update(base_ips)

    check_http_headers(target_domain)
    all_found_ips.update(get_mx_ips(target_domain))
    all_found_ips.update(find_subdomain_ips(target_domain, SUBDOMAINS_TO_CHECK))
    all_found_ips.update(search_shodan(target_domain, SHODAN_API_KEY))

    # --- Final Report ---
    print("\n" + "="*50)
    print("--- 💡 Investigation Complete: Final Report 💡 ---")
    print("="*50)

    if not all_found_ips:
        print("\nCould not find any IP addresses. Review the HTTP header logs above for clues.")
        return

    origin_candidates = sorted(list(all_found_ips - base_ips))
    
    print("\nPublic-facing IP Addresses (Likely CDN/Proxy):")
    if base_ips:
        for ip in sorted(list(base_ips)):
            # Perform WHOIS check on public IPs as well for context
            owner_info = check_ip_whois(ip)
            print(f"  - {ip:<15} | {owner_info}")
    else:
        print("  None found directly for the base domain.")

    print("\nPotential Origin IP Address Candidates:")
    if origin_candidates:
        print("  (These IPs were found via other methods and are worth investigating)")
        for ip in origin_candidates:
            owner_info = check_ip_whois(ip)
            print(f"  - {ip:<15} | {owner_info}  <-- ✨")
    else:
        print("  No unique candidates found. The server appears well-hidden behind its public-facing IPs.")

if __name__ == "__main__":
    try:
        main()
    except ImportError as e:
        print(f"❌ Missing Dependency: {e.name}")
        print("Please install all required libraries with the command:")
        print("pip install dnspython requests shodan argparse ipwhois")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nExecution cancelled by user. Exiting.")
        sys.exit(0)
