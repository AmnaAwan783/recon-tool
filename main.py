#!/usr/bin/env python3
"""
recon-tool — Modular Reconnaissance CLI
Developed for: ITSOLERA PVT LTD Summer Internship — Offensive Security (Tool Development)

Usage examples:
    python main.py example.com --all
    python main.py example.com --whois --dns
    python main.py example.com --subdomains --no-resolve
    python main.py example.com --ports --banners
    python main.py example.com --all --format html -o report.html -vv

IMPORTANT: Only run active recon (--ports, --banners) against systems you
own or are explicitly authorized to test.
"""
import argparse
import logging
import socket
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import whois_lookup, dns_enum, subdomain_enum, port_scan, banner_grab, tech_detect
from modules.logger_setup import setup_logger
from report import generator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-tool",
        description="Modular reconnaissance tool for authorized penetration testing engagements.",
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")

    passive = parser.add_argument_group("Passive recon")
    passive.add_argument("--whois", action="store_true", help="Run WHOIS lookup")
    passive.add_argument("--dns", action="store_true", help="Run DNS enumeration (A, MX, TXT, NS, ...)")
    passive.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration (crt.sh, OTX)")
    passive.add_argument("--no-resolve", action="store_true", help="Skip resolving subdomains to IPs")

    active = parser.add_argument_group("Active recon")
    active.add_argument("--ports", action="store_true", help="Run port scan")
    active.add_argument("--use-nmap", action="store_true", help="Use system nmap binary instead of socket scan")
    active.add_argument("--banners", action="store_true", help="Grab banners on open ports (requires --ports)")
    active.add_argument("--tech", action="store_true", help="Detect web technologies")

    parser.add_argument("--all", action="store_true", help="Run every module")

    out = parser.add_argument_group("Output")
    out.add_argument("--format", choices=["txt", "html"], default="txt", help="Report format (default: txt)")
    out.add_argument("-o", "--output", help="Output report file path (default: <domain>_report.<ext>)")

    parser.add_argument("-v", "--verbose", action="count", default=0,
                         help="Increase verbosity (-v info, -vv debug)")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    setup_logger(min(args.verbose, 2))
    logger = logging.getLogger("recon.main")

    domain = args.domain
    results = {}

    run_whois = args.whois or args.all
    run_dns = args.dns or args.all
    run_subdomains = args.subdomains or args.all
    run_ports = args.ports or args.all
    run_banners = args.banners or args.all
    run_tech = args.tech or args.all

    if not any([run_whois, run_dns, run_subdomains, run_ports, run_banners, run_tech]):
        parser.error("No modules selected. Use --all or specify at least one module flag (see --help).")

    logger.info(f"Starting reconnaissance against: {domain}")

    if run_whois:
        results["whois"] = whois_lookup.run(domain)

    if run_dns:
        results["dns"] = dns_enum.run(domain)

    if run_subdomains:
        results["subdomains"] = subdomain_enum.run(domain, resolve=not args.no_resolve)

    open_ports = []
    resolved_ip = None
    if run_ports:
        port_result = port_scan.run(domain, use_nmap=args.use_nmap)
        results["portscan"] = port_result
        if port_result.get("success") and "open_ports" in port_result.get("data", {}):
            open_ports = port_result["data"]["open_ports"]
            resolved_ip = port_result["data"].get("resolved_ip")

    if run_banners:
        if not resolved_ip:
            try:
                resolved_ip = socket.gethostbyname(domain)
            except socket.gaierror:
                resolved_ip = None
        if resolved_ip and open_ports:
            results["banner_grab"] = banner_grab.run(domain, resolved_ip, open_ports)
        else:
            logger.warning("Skipping banner grab — no resolved IP / open ports available. Run with --ports too.")
            results["banner_grab"] = {"module": "banner_grab", "target": domain, "success": False,
                                       "error": "No open ports to grab banners from (run with --ports)"}

    if run_tech:
        results["tech_detect"] = tech_detect.run(domain)

    ext = "html" if args.format == "html" else "txt"
    output_path = args.output or f"{domain}_report.{ext}"
    generator.write_report(domain, results, output_path, fmt=args.format)

    print(f"\n[+] Reconnaissance complete for {domain}")
    print(f"[+] Report saved to: {output_path}")


if __name__ == "__main__":
    main()
