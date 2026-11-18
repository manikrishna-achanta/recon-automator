"""
modules/report_gen.py
Generates a clean HTML report from all recon results.
"""

import os
from datetime import datetime


def generate_report(results, session_dir):
    """
    Generate a self-contained HTML report from recon results.
    Returns path to the generated report.
    """
    domain = results.get("domain", "unknown")
    timestamp = results.get("timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
    subdomains = results.get("subdomains", [])
    ports = results.get("ports", {})
    http_probes = results.get("http_probes", [])
    whois = results.get("whois", {})

    # --- Build HTML sections ---

    # Subdomains table
    if subdomains:
        sub_rows = "\n".join(f"<tr><td>{s}</td></tr>" for s in subdomains)
        sub_section = f"""
        <section>
          <h2>🔍 Subdomains ({len(subdomains)} found)</h2>
          <table><thead><tr><th>Hostname</th></tr></thead><tbody>{sub_rows}</tbody></table>
        </section>"""
    else:
        sub_section = "<section><h2>🔍 Subdomains</h2><p class='muted'>Module not run or no results.</p></section>"

    # Port scan table
    if ports:
        port_rows = ""
        for host, port_list in ports.items():
            for p in port_list:
                banner = p.get("banner", "")[:80]
                port_rows += f"<tr><td>{host}</td><td>{p['port']}</td><td>{p['service']}</td><td class='banner'>{banner}</td></tr>"
        port_section = f"""
        <section>
          <h2>🔌 Open Ports</h2>
          <table>
            <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th></tr></thead>
            <tbody>{port_rows}</tbody>
          </table>
        </section>"""
    else:
        port_section = "<section><h2>🔌 Open Ports</h2><p class='muted'>Module not run or no results.</p></section>"

    # HTTP probe table
    live_probes = [h for h in http_probes if h.get("status") == "live"]
    if live_probes:
        http_rows = ""
        for h in live_probes:
            techs = ", ".join(h.get("techs", [])) or "—"
            http_rows += (
                f"<tr>"
                f"<td><a href='{h['url']}' target='_blank'>{h['url']}</a></td>"
                f"<td>{h['code']}</td>"
                f"<td>{h.get('title', '') or '—'}</td>"
                f"<td>{h.get('server', '') or '—'}</td>"
                f"<td>{techs}</td>"
                f"</tr>"
            )
        http_section = f"""
        <section>
          <h2>🌐 HTTP Probes ({len(live_probes)} live)</h2>
          <table>
            <thead><tr><th>URL</th><th>Code</th><th>Title</th><th>Server</th><th>Technologies</th></tr></thead>
            <tbody>{http_rows}</tbody>
          </table>
        </section>"""
    else:
        http_section = "<section><h2>🌐 HTTP Probes</h2><p class='muted'>Module not run or no results.</p></section>"

    # WHOIS section
    whois_content = ""
    if whois:
        whois_content = f"""
        <section>
          <h2>📋 WHOIS</h2>
          <table>
            <tr><th>Registrar</th><td>{whois.get('registrar','—')}</td></tr>
            <tr><th>Created</th><td>{whois.get('created','—')}</td></tr>
            <tr><th>Expires</th><td>{whois.get('expires','—')}</td></tr>
            <tr><th>Name Servers</th><td>{', '.join(whois.get('name_servers', [])) or '—'}</td></tr>
          </table>
        </section>"""
    else:
        whois_content = "<section><h2>📋 WHOIS</h2><p class='muted'>Module not run or no results.</p></section>"

    # --- Full HTML ---
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report — {domain}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; padding: 2rem; }}
  header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  header h1 {{ font-size: 1.6rem; color: var(--accent); }}
  header p {{ color: var(--muted); margin-top: 0.3rem; font-size: 0.85rem; }}
  .meta {{ display: flex; gap: 2rem; margin-top: 1rem; flex-wrap: wrap; }}
  .meta span {{ background: var(--surface); border: 1px solid var(--border); 
               padding: 0.3rem 0.7rem; border-radius: 4px; font-size: 0.8rem; }}
  section {{ margin-bottom: 2.5rem; }}
  h2 {{ font-size: 1.1rem; color: var(--accent); margin-bottom: 1rem; 
        padding-bottom: 0.4rem; border-bottom: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ background: var(--surface); color: var(--muted); text-align: left; 
        padding: 0.5rem 0.8rem; border: 1px solid var(--border); font-weight: normal; }}
  td {{ padding: 0.45rem 0.8rem; border: 1px solid var(--border); vertical-align: top; }}
  tr:nth-child(even) td {{ background: #0d1117; }}
  tr:nth-child(odd) td {{ background: #161b22; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .muted {{ color: var(--muted); font-style: italic; }}
  .banner {{ color: var(--yellow); font-size: 0.78rem; }}
  footer {{ color: var(--muted); font-size: 0.75rem; margin-top: 3rem; 
            border-top: 1px solid var(--border); padding-top: 1rem; }}
</style>
</head>
<body>
<header>
  <h1>⚡ recon-automator — Scan Report</h1>
  <p>github.com/manikrishna-achanta</p>
  <div class="meta">
    <span>🎯 Target: <strong>{domain}</strong></span>
    <span>📅 {timestamp}</span>
    <span>🔍 Subdomains: {len(subdomains)}</span>
    <span>🔌 Open Ports: {sum(len(v) for v in ports.values())}</span>
    <span>🌐 Live HTTP: {len(live_probes)}</span>
  </div>
</header>

{whois_content}
{sub_section}
{port_section}
{http_section}

<footer>
  Generated by recon-automator | github.com/manikrishna-achanta | {timestamp}
</footer>
</body>
</html>"""

    report_path = os.path.join(session_dir, f"report_{domain}.html")
    with open(report_path, "w") as f:
        f.write(html)

    return report_path
