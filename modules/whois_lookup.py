"""
modules/whois_lookup.py
WHOIS lookup using the python-whois library with fallback to raw socket query.
"""

import os
import socket


def raw_whois(domain):
    """Fallback: raw WHOIS query to whois.iana.org."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("whois.iana.org", 43))
        s.sendall((domain + "\r\n").encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        return response.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"Raw WHOIS failed: {e}"


def whois_lookup(domain, session_dir):
    """
    Perform WHOIS lookup on domain.
    Returns dict with parsed fields.
    """
    result = {"domain": domain, "raw": "", "registrar": "", "created": "", "expires": "", "name_servers": []}

    try:
        import whois  # python-whois
        w = whois.whois(domain)
        result["raw"] = str(w)
        result["registrar"] = str(w.registrar or "")
        result["created"] = str(w.creation_date or "")
        result["expires"] = str(w.expiration_date or "")
        ns = w.name_servers or []
        result["name_servers"] = [str(n) for n in (ns if isinstance(ns, list) else [ns])]

        print(f"  [+] Registrar  : {result['registrar']}")
        print(f"  [+] Created    : {result['created']}")
        print(f"  [+] Expires    : {result['expires']}")
        print(f"  [+] Name Servers: {', '.join(result['name_servers'])}")

    except ImportError:
        print("  [!] python-whois not installed. Falling back to raw WHOIS query.")
        result["raw"] = raw_whois(domain)
        print(result["raw"][:500])
    except Exception as e:
        print(f"  [!] WHOIS error: {e}")
        result["raw"] = raw_whois(domain)

    # Save
    out_file = os.path.join(session_dir, "whois.txt")
    with open(out_file, "w") as f:
        f.write(f"# WHOIS results for {domain}\n")
        f.write(result["raw"])
    print(f"  [>] Saved to {out_file}")

    return result
