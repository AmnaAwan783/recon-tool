# Recon Tool

A modular reconnaissance tool made for our ITSOLERA PVT LTD Summer Internship task (Offensive Security - Tool Development). It automates the info-gathering phase of a pentest - WHOIS, DNS records, subdomains, port scanning, banner grabbing and basic tech detection - and puts everything into one report.

Made by Team Beta.

## Important - authorized use only

This tool does active scanning (port scans, banner grabs, HTTP requests to the target). Only run it on domains/hosts you own or have permission to test. We used `example.com` for all our testing since it's reserved by IANA for exactly this purpose.

## What it does

| Type | Module | Flag | What it gets |
|---|---|---|---|
| Passive | WHOIS | `--whois` | Registrar, creation/expiry dates, name servers, status |
| Passive | DNS enumeration | `--dns` | A, AAAA, MX, TXT, NS, SOA, CNAME records |
| Passive | Subdomain enumeration | `--subdomains` | Pulls from crt.sh and AlienVault OTX, resolves IPs of found subdomains |
| Active | Port scan | `--ports` | Threaded TCP connect scan (or use real nmap with `--use-nmap`) |
| Active | Banner grabbing | `--banners` | Grabs service banners on ports found open by `--ports` |
| Active | Tech detection | `--tech` | Detects CMS/server/framework from headers, HTML and cookies |
| Report | - | `--format txt/html` | Generates the final report with timestamps and resolved IPs |

Every module works on its own through its flag, or you can just run `--all` to do everything at once.

## Setup

```bash
git clone <repo-url>
cd recon-tool
pip install -r requirements.txt
```

If you want to use `--use-nmap`, you need nmap installed on your system separately.

## How to use it

```bash
# run everything
python main.py example.com --all

# only passive recon
python main.py example.com --whois --dns --subdomains

# only active recon, using nmap, verbose output
python main.py example.com --ports --use-nmap --banners -vv

# get an html report instead of txt
python main.py example.com --all --format html -o reports/example_report.html
```

### All CLI flags
domain                 target domain, e.g example.com
Passive recon:
--whois               WHOIS lookup
--dns                 DNS enumeration
--subdomains          subdomain enumeration
--no-resolve          don't resolve subdomain IPs
Active recon:
--ports               port scan
--use-nmap            use nmap instead of socket scan
--banners             banner grabbing (needs --ports)
--tech                tech detection
--all                 run everything
Output:
--format {txt,html}   report format, default txt
-o, --output          where to save the report
-v, -vv                verbosity (info / debug)

## Project structure
recon-tool/
├── main.py                    # CLI entry point
├── modules/
│   ├── whois_lookup.py
│   ├── dns_enum.py
│   ├── subdomain_enum.py
│   ├── port_scan.py
│   ├── banner_grab.py
│   ├── tech_detect.py
│   └── logger_setup.py        # logging config, verbosity levels
├── report/
│   └── generator.py           # builds the txt/html report
├── sample_reports/             # example reports for example.com
├── requirements.txt
├── Dockerfile
└── README.md

## Sample report

Check `sample_reports/example.com_report.txt` and `.html` for example output we generated.

## Known limitations

During our testing we ran into a couple of things worth mentioning:

- **crt.sh and AlienVault OTX are free public APIs** and sometimes they time out or rate-limit (we hit a 429 from OTX a few times while testing). When this happens the tool doesn't crash - it just logs a warning and continues with whatever it could get. So subdomain count can vary a bit between runs depending on how these services are behaving at the time.
- Similarly, DNS lookups for some record types can occasionally time out if there's network slowness (we saw this a couple of times with TXT records specifically). Same handling - it logs it and moves on instead of stopping the whole scan.
- Because of the above, the tool is built so that if one module or one record type fails, the rest of the recon still completes and gets reported. Nothing crashes because of an external service being slow.

## Docker

```bash
docker build -t recon-tool .
docker run --rm -v $(pwd)/sample_reports:/app/sample_reports recon-tool example.com --all -o sample_reports/report.txt
```

## Some design decisions

- Port scanning uses raw sockets by default so the tool doesn't need nmap installed to work at all. `--use-nmap` is there as an option if you want to use real nmap.
- Subdomain enumeration only uses passive sources (crt.sh, OTX) - no active brute forcing, so it stays on the safer/quieter side by default.
- Every module returns the same kind of dict format (module name, target, success, data or error), so the report generator doesn't need separate code for each module and it's easy to add new modules later.
- Logging uses Python's built-in `logging` module with -v/-vv flags instead of plain print statements.

## Disclaimer

Built for our internship task, for educational purposes. We are not responsible for any misuse of this tool.