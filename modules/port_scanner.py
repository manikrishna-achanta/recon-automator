"""
modules/port_scanner.py
Multi-threaded TCP port scanner with banner grabbing.
"""

import os
import socket
import concurrent.futures


# Common service names for well-known ports
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    11211: "Memcached", 9200: "Elasticsearch", 5900: "VNC"
}


def parse_port_range(port_range_str):
    """Parse '1-1024' or '80,443,8080' into a list of ints."""
    ports = []
    for part in port_range_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def grab_banner(host, port, timeout):
    """Attempt to grab a service banner."""
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner[:200] if banner else ""
    except Exception:
        return ""


def scan_port(host, port, timeout):
    """Scan a single port. Returns dict if open, None if closed."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            service = SERVICE_MAP.get(port, "unknown")
            banner = grab_banner(host, port, timeout)
            return {"port": port, "state": "open", "service": service, "banner": banner}
    except Exception:
        pass
    return None


def scan_host(host, ports, threads, timeout):
    """Scan all ports on a single host."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda x: x["port"])


def scan_ports(targets, port_range_str, threads, timeout, session_dir):
    """
    Scan ports on a list of target hosts.
    Returns dict: {host: [{"port": int, "state": str, "service": str, "banner": str}]}
    """
    ports = parse_port_range(port_range_str)
    print(f"  [>] Scanning {len(ports)} port(s) per host with {threads} threads...")

    results = {}
    out_lines = []

    for host in targets:
        print(f"  [>] Scanning {host}...")
        open_ports = scan_host(host, ports, threads, timeout)
        results[host] = open_ports
        for p in open_ports:
            banner_str = f" | {p['banner']}" if p['banner'] else ""
            line = f"{host}:{p['port']}\t{p['service']}{banner_str}"
            print(f"    [+] {line}")
            out_lines.append(line)

    # Save results
    out_file = os.path.join(session_dir, "ports.txt")
    with open(out_file, "w") as f:
        f.write("# Port scan results\n# host:port\tservice\tbanner\n")
        f.write("\n".join(out_lines) + "\n")
    print(f"  [>] Saved to {out_file}")

    return results
