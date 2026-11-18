# recon-automator

**A pure-Python external reconnaissance framework — and a study in making recon automation reliable where the naive approach fails.**

> **Engineering question.** Recon tooling looks trivial until it meets the real
> internet: port-43 WHOIS is blocked or rate-limited, blocking lookup libraries
> hang forever, and serial scanning is unusably slow. *What does it take to make
> each recon primitive robust* — degrade gracefully, never hang, and parallelise
> correctly? This project is the answer, built from scratch in the standard library
> plus minimal dependencies rather than shelling out to existing tools.

It is scoped to **reconnaissance only** — passive and active information gathering.
See [Scope & ethics](#scope--ethics).

---

## Modules

| Module | File | What it does | The reliability problem it solves |
|--------|------|--------------|-----------------------------------|
| **WHOIS / RDAP** | `whois_lookup.py` | registration data lookup | 4-tier fallback so a blocked port 43 never kills the lookup |
| **Subdomains** | `subdomain_enum.py` | threaded DNS brute-force | I/O-bound parallelism done right |
| **Ports** | `port_scanner.py` | TCP connect-scan + banner grab | bounded timeouts, no hangs |
| **HTTP** | `http_probe.py` | tech/header fingerprinting of live hosts | distinguishes live from dead cleanly |
| **Report** | `report_gen.py` | consolidated HTML report | — |

### The part worth reading: the WHOIS/RDAP fallback chain
`whois_lookup.py` tries, in order, and stops at the first that works:

1. **RDAP over HTTPS (port 443)** — the modern replacement for WHOIS; bypasses
   port-43 blocking entirely. TLD-to-registry routing uses the IANA RDAP bootstrap
   (`data.iana.org/rdap/dns.json`) with a built-in fallback table for ~18 common TLDs.
2. **`python-whois` library** — wrapped in a hard `SIGALRM` timeout so a blocking
   call can never hang the run (Linux).
3. **System `whois` binary** — if present.
4. **Graceful failure** — a structured "unavailable" result, never a crash.

This chain is the project's actual engineering content: it encodes *why* port-43
WHOIS is unreliable in production and what to do about it, rather than assuming the
happy path.

---

## Install & run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Everything
python3 recon.py -d example.com --all

# Pick modules
python3 recon.py -d example.com --whois --subdomains --ports
python3 recon.py -d example.com --subdomains --wordlist wordlists/subdomains.txt --threads 50
python3 recon.py -d example.com --ports --ports-range 1-65535 --timeout 2
```

Results (JSON per module + an HTML report) are written to
`output/<domain>_<timestamp>/`.

---

## Repository layout

```
recon-automator/
├── recon.py                 # CLI orchestrator
├── wordlists/subdomains.txt # default brute-force wordlist
└── modules/
    ├── whois_lookup.py      # 4-tier RDAP/WHOIS fallback  ← the interesting part
    ├── subdomain_enum.py    # threaded DNS enumeration
    ├── port_scanner.py      # threaded TCP connect-scan + banners
    ├── http_probe.py        # HTTP/HTTPS fingerprinting
    └── report_gen.py        # HTML report
```

---

## Scope & ethics

This is a **reconnaissance** framework. It intentionally does **not** include any
exploitation, payload-generation, or shell-delivery capability. An earlier private
build had a reverse-shell payload module; it is deliberately excluded from this
public repository because (a) the project's scope is information gathering, and
(b) publishing offensive payload generators invites both automated flagging and
genuine misuse.

Use only against assets you own or are explicitly authorised to test. Unauthorised
scanning may be illegal in your jurisdiction.

### Known limitations
- `SIGALRM`-based timeouts are Linux/Unix only (the tool is developed on Kali).
- Subdomain discovery is brute-force only; no passive/CT-log sources yet.
- Banner grabbing is best-effort and does not do full service version detection.

---

## License
MIT — see `LICENSE`.
