import argparse
import requests
from urllib.parse import urlparse, parse_qs
from termcolor import cprint, colored
from collections import defaultdict
from tqdm import tqdm
import os
import re
import time

def print_banner():
    """Print the banner for the tool with updated project name and contact details."""
    banner = r"""
                                _ _                      
                             | (_)                _    
  ____ _   _     ____ ____ _ | |_  ____ ____ ____| |_  
 / _  | \ / )   / ___) _  ) || | |/ ___) _  ) ___)  _) 
( (/ / ) X (   | |  ( (/ ( (_| | | |  ( (/ ( (___| |__ 
 \____|_/ \_)  |_|   \____)____|_|_|   \____)____)\___)
                                                       
                                                                                     
                                                                                     

                 ex-redirect | Automated Open Redirect Finder

    [  Author   ] rootdr
    [  Twitter  ] @R00TDR
    [  Telegram ] https://t.me/RootDr
    """
    print(colored(banner, "magenta"))

def fetch_wayback_urls(domain, retries=3, delay=5):
    query = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&collapse=urlkey"
    for attempt in range(1, retries + 1):
        try:
            cprint(f"[i] Attempt {attempt} to fetch Wayback URLs for {domain}...", "blue")
            res = requests.get(query, timeout=15)
            if res.status_code == 200:
                return list(set(res.text.splitlines()))
        except Exception as e:
            cprint(f"[!] Error: {e}", "yellow")
            if attempt < retries:
                cprint("[*] Retrying in 5 seconds...", "cyan")
                time.sleep(delay)
    cprint("[X] Failed to fetch Wayback URLs after multiple attempts.", "red")
    return []

def is_potential_redirect(url):
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for values in params.values():
            for val in values:
                if re.match(r'^(https?:\/\/|\/)', val.strip()):
                    return True
    except:
        pass
    return False

def contains_wordpress_path(url):
    wp_keywords = [
        'wp-content', 'wp-admin', 'wp-login', 'wp-json',
        'xmlrpc.php', '/wp/', '/wordpress', '/wp1', '/wp2'
    ]
    url = url.lower()
    parsed = urlparse(url)
    if parsed.path == "/blog":
        return True
    return any(kw in url for kw in wp_keywords)

def group_by_subdomain(urls, main_domain):
    grouped = defaultdict(list)
    for url in urls:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if hostname.endswith(main_domain):
            grouped[hostname].append(url)
    return grouped

def is_live(url):
    try:
        res = requests.head(url, timeout=5, allow_redirects=True)
        return res.status_code < 400
    except:
        return False

def filter_live_urls(urls):
    live = []
    for url in tqdm(urls, desc="🔍 Checking live URLs", ncols=75):
        if is_live(url):
            live.append(url)
    return live

def save_results(domain, subdomain, urls):
    folder = domain
    os.makedirs(folder, exist_ok=True)
    filepath = os.path.join(folder, f"{subdomain}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        for url in urls:
            f.write(url + "\n")
    cprint(f"[+] {len(urls)} potential open redirects saved for {subdomain}.", "green")

def main():
    print_banner()  # ✅ This line ensures the banner is displayed

    parser = argparse.ArgumentParser(description="Open Redirect Finder via Wayback Machine")
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-s", "--subdomains", action="store_true", help="Scan all subdomains (via Wayback wildcard)")
    parser.add_argument("-l", "--live", action="store_true", help="Only save live open redirect URLs")
    parser.add_argument("-wp", "--wordpress", action="store_true", help="Ignore WordPress-related paths")
    args = parser.parse_args()

    domain = args.target.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc

    scan_target = f"*.{domain}" if args.subdomains else domain

    cprint(f"[*] Fetching Wayback URLs for {scan_target} ...", "cyan")
    urls = fetch_wayback_urls(scan_target)
    if not urls:
        return

    if args.subdomains:
        grouped = group_by_subdomain(urls, domain)
        if not grouped:
            cprint("[-] No subdomains found. Scanning only main domain.", "red")

        for sub, sub_urls in grouped.items():
            filtered = [url for url in sub_urls if is_potential_redirect(url)]
            if args.wordpress:
                filtered = [url for url in filtered if not contains_wordpress_path(url)]
            if args.live:
                filtered = filter_live_urls(filtered)
            if filtered:
                save_results(domain, sub, filtered)
            else:
                cprint(f"[-] 0 potential open redirects found for {sub}.", "red")
    else:
        filtered = [url for url in urls if is_potential_redirect(url)]
        if args.wordpress:
            filtered = [url for url in filtered if not contains_wordpress_path(url)]
        if args.live:
            filtered = filter_live_urls(filtered)
        if filtered:
            save_results(domain, domain, filtered)
        else:
            cprint(f"[-] 0 potential open redirects found for {domain}.", "red")

if __name__ == "__main__":
    main()
