"""
modules/subdomain_enum.py
Subdomain enumeration via DNS resolution with threading.
"""

import os
import socket
import concurrent.futures
from pathlib import Path


DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "api", "dev",
    "staging", "test", "admin", "portal", "dashboard", "login", "secure",
    "cdn", "static", "assets", "blog", "shop", "store", "app", "mobile",
    "m", "webmail", "ns1", "ns2", "mx", "remote", "internal", "corp",
    "intranet", "git", "gitlab", "jenkins", "jira", "confluence", "wiki"
]


def resolve_subdomain(subdomain, domain, timeout):
    """Attempt DNS resolution of subdomain.domain. Returns subdomain string if resolved."""
    fqdn = f"{subdomain}.{domain}"
    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(fqdn)
        return {"host": fqdn, "ip": ip}
    except (socket.gaierror, socket.timeout):
        return None


def load_wordlist(path):
    """Load wordlist from file or fall back to built-in list."""
    if path and os.path.isfile(path):
        with open(path, "r") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        print(f"  [>] Loaded {len(words)} words from {path}")
        return words
    else:
        print(f"  [!] Wordlist not found at '{path}'. Using built-in list ({len(DEFAULT_WORDLIST)} entries).")
        return DEFAULT_WORDLIST


def enumerate_subdomains(domain, wordlist_path, threads, timeout, session_dir):
    """
    Enumerate subdomains using DNS resolution.
    Returns list of dicts: [{"host": str, "ip": str}, ...]
    """
    words = load_wordlist(wordlist_path)
    found = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(resolve_subdomain, word, domain, timeout): word
            for word in words
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(f"  [+] {result['host']} -> {result['ip']}")
                found.append(result)

    # Save results
    out_file = os.path.join(session_dir, "subdomains.txt")
    with open(out_file, "w") as f:
        f.write(f"# Subdomain enumeration results for {domain}\n")
        for entry in found:
            f.write(f"{entry['host']}\t{entry['ip']}\n")
    print(f"  [>] Saved to {out_file}")

    return [entry["host"] for entry in found]
