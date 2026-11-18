"""
modules/http_probe.py
HTTP/HTTPS probing: status codes, headers, title, tech fingerprinting.
"""

import os
import re
import socket
import urllib.request
import urllib.error
import ssl


# Common tech fingerprints from response headers / body
TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "WordPress"],
    "Joomla": ["Joomla!", "/components/com_"],
    "Drupal": ["Drupal", "drupal.js"],
    "Laravel": ["laravel_session", "Laravel"],
    "Django": ["csrfmiddlewaretoken", "__django"],
    "React": ["react", "reactDOM"],
    "Angular": ["ng-version", "angular"],
    "Apache": ["Apache"],
    "Nginx": ["nginx"],
    "IIS": ["Microsoft-IIS"],
    "PHP": ["X-Powered-By: PHP", ".php"],
    "ASP.NET": ["ASP.NET", "X-AspNet-Version"],
}


def extract_title(html):
    """Extract <title> from HTML."""
    match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip()[:100] if match else ""


def fingerprint_tech(headers_str, body):
    """Identify technologies from headers and page body."""
    combined = headers_str + body[:5000]
    detected = []
    for tech, sigs in TECH_SIGNATURES.items():
        if any(sig.lower() in combined.lower() for sig in sigs):
            detected.append(tech)
    return detected


def probe_url(url, timeout):
    """
    Probe a single URL. Returns dict with status, headers, title, techs.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (recon-automator)"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(10000).decode("utf-8", errors="ignore")
            headers_str = str(resp.headers)
            title = extract_title(body)
            techs = fingerprint_tech(headers_str, body)
            return {
                "url": url,
                "status": "live",
                "code": resp.status,
                "title": title,
                "server": resp.headers.get("Server", ""),
                "x_powered_by": resp.headers.get("X-Powered-By", ""),
                "techs": techs,
                "redirect": resp.url if resp.url != url else "",
            }
    except urllib.error.HTTPError as e:
        return {
            "url": url, "status": "live", "code": e.code,
            "title": "", "server": "", "x_powered_by": "", "techs": [], "redirect": ""
        }
    except Exception:
        return {"url": url, "status": "dead", "code": 0,
                "title": "", "server": "", "x_powered_by": "", "techs": [], "redirect": ""}


def probe_http(targets, timeout, session_dir):
    """
    Probe HTTP and HTTPS for each target host.
    Returns list of probe result dicts.
    """
    results = []
    out_lines = []

    for host in targets:
        for scheme in ["http", "https"]:
            url = f"{scheme}://{host}"
            result = probe_url(url, timeout)
            results.append(result)
            if result["status"] == "live":
                tech_str = ", ".join(result["techs"]) if result["techs"] else "unknown"
                line = (
                    f"{url} [{result['code']}] | "
                    f"Title: {result['title'] or 'N/A'} | "
                    f"Server: {result['server'] or 'N/A'} | "
                    f"Techs: {tech_str}"
                )
                print(f"  [+] {line}")
                out_lines.append(line)
            else:
                print(f"  [-] {url} -> dead")

    # Save results
    out_file = os.path.join(session_dir, "http_probes.txt")
    with open(out_file, "w") as f:
        f.write("# HTTP/HTTPS probe results\n")
        f.write("\n".join(out_lines) + "\n")
    print(f"  [>] Saved to {out_file}")

    return results
