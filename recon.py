#!/usr/bin/env python3
"""
recon-automator — Modular reconnaissance framework
Research/portfolio artifact | Mani Krishna

A pure-Python external reconnaissance toolkit built to study the reliability
engineering behind recon automation — specifically how to make WHOIS, DNS,
and port/service discovery robust in environments where the naive approach
(port-43 WHOIS, blocking libraries, serial scanning) fails or hangs.

Modules:
  - WHOIS/RDAP   : 4-tier fallback (RDAP-over-HTTPS → python-whois → system
                   binary → graceful fail) to survive port-43 blocking
  - Subdomains   : threaded DNS brute-force enumeration
  - Ports        : threaded TCP connect-scan with banner grabbing
  - HTTP         : technology/header fingerprinting of live hosts
  - Report       : consolidated HTML report

Usage:
  python3 recon.py -d example.com --all
  python3 recon.py -d example.com --whois --subdomains --ports

NOTE: This public edition intentionally omits the exploitation/payload-delivery
module. This repository is scoped to *reconnaissance* (passive and active
information gathering) only. Use exclusively against assets you are authorised
to test.
"""

import argparse
import sys
import os
from datetime import datetime
from modules.subdomain_enum import enumerate_subdomains
from modules.port_scanner import scan_ports
from modules.http_probe import probe_http
from modules.whois_lookup import whois_lookup
from modules.report_gen import generate_report

BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  recon-automator | Modular Reconnaissance Framework
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="recon-automator: Modular external reconnaissance framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: output/)")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--ports", action="store_true", help="Run port scanning on discovered hosts")
    parser.add_argument("--http", action="store_true", help="Probe HTTP/HTTPS on live hosts")
    parser.add_argument("--whois", action="store_true", help="Run WHOIS/RDAP lookup on target domain")
    parser.add_argument("--all", action="store_true", help="Run all reconnaissance modules")
    parser.add_argument("--wordlist", default="wordlists/subdomains.txt",
                        help="Wordlist for subdomain bruteforce (default: wordlists/subdomains.txt)")
    parser.add_argument("--ports-range", default="1-1024",
                        help="Port range to scan (default: 1-1024)")
    parser.add_argument("--threads", type=int, default=50,
                        help="Number of threads (default: 50)")
    parser.add_argument("--report", action="store_true", help="Generate HTML report after all modules")
    parser.add_argument("--timeout", type=int, default=3, help="Connection timeout in seconds (default: 3)")
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    # Normalize flags
    run_all        = args.all
    run_subdomains = args.subdomains or run_all
    run_ports      = args.ports      or run_all
    run_http       = args.http       or run_all
    run_whois      = args.whois      or run_all

    if not any([run_subdomains, run_ports, run_http, run_whois]):
        print("[!] No module selected. Use --all or choose specific modules. Run with -h for help.")
        sys.exit(1)

    # Prepare output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = os.path.join(args.output, f"{args.domain}_{timestamp}")
    os.makedirs(session_dir, exist_ok=True)
    print(f"[*] Session output directory: {session_dir}")
    print(f"[*] Target: {args.domain}")
    print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    results = {
        "domain"     : args.domain,
        "timestamp"  : timestamp,
        "session_dir": session_dir,
        "subdomains" : [],
        "ports"      : {},
        "http_probes": [],
        "whois"      : {},
    }

    # --- WHOIS / RDAP ---
    if run_whois:
        print("[*] Running WHOIS/RDAP lookup...")
        results["whois"] = whois_lookup(args.domain, session_dir)

    # --- SUBDOMAIN ENUMERATION ---
    if run_subdomains:
        print(f"[*] Running subdomain enumeration (wordlist: {args.wordlist}, threads: {args.threads})...")
        results["subdomains"] = enumerate_subdomains(
            args.domain, args.wordlist, args.threads, args.timeout, session_dir
        )
        print(f"[+] Found {len(results['subdomains'])} subdomains.\n")

    # --- PORT SCANNING ---
    if run_ports:
        targets = results["subdomains"] if results["subdomains"] else [args.domain]
        print(f"[*] Port scanning {len(targets)} host(s) on range {args.ports_range}...")
        results["ports"] = scan_ports(
            targets, args.ports_range, args.threads, args.timeout, session_dir
        )
        open_count = sum(len(v) for v in results["ports"].values())
        print(f"[+] Found {open_count} open port(s) across {len(targets)} host(s).\n")

    # --- HTTP PROBE ---
    if run_http:
        targets = results["subdomains"] if results["subdomains"] else [args.domain]
        print(f"[*] Probing HTTP/HTTPS on {len(targets)} host(s)...")
        results["http_probes"] = probe_http(targets, args.timeout, session_dir)
        live = [h for h in results["http_probes"] if h.get("status") == "live"]
        print(f"[+] {len(live)} live HTTP host(s) found.\n")

    # --- REPORT ---
    if args.report or run_all:
        print("[*] Generating HTML report...")
        report_path = generate_report(results, session_dir)
        print(f"[+] Report saved to: {report_path}\n")

    print(f"[+] Recon complete. All output saved to: {session_dir}")


if __name__ == "__main__":
    main()
