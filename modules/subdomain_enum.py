"""
Subdomain Enumeration Module
Uses public, passive data sources only — certificate transparency logs (crt.sh)
and AlienVault OTX. No active queries are sent to the target itself.
"""
import logging
import socket
import requests
import re

logger = logging.getLogger("recon.subdomains")

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

HEADERS = {"User-Agent": "recon-tool/1.0 (educational/internship use)"}
HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
)

def _from_crtsh(domain: str) -> set:
    found = set()

    try:
        resp = requests.get(
            CRTSH_URL.format(domain=domain),
            headers=HEADERS,
            timeout=15,
        )
        resp.raise_for_status()

        entries = resp.json()

        for entry in entries:
            name_value = entry.get("name_value", "")

            for sub in name_value.splitlines():
                sub = sub.strip().lower()

                # Remove wildcard prefix (*.example.com -> example.com)
                if sub.startswith("*."):
                    sub = sub[2:]

                # Ignore email addresses
                if "@" in sub:
                    continue

                # Ignore certificate titles / organization names
                if " " in sub:
                    continue

                # Must look like a valid hostname
                if not HOSTNAME_RE.match(sub):
                    continue

                # Must be the target domain or one of its subdomains
                if sub == domain or sub.endswith("." + domain):
                    found.add(sub)

        logger.info(f"crt.sh returned {len(found)} unique subdomain(s)")

    except Exception as e:
        logger.warning(f"crt.sh query failed: {e}")

    return found

def _from_otx(domain: str) -> set:
    found = set()

    try:
        resp = requests.get(
            OTX_URL.format(domain=domain),
            headers=HEADERS,
            timeout=15,
        )

        if resp.status_code == 200:
            data = resp.json()

            for record in data.get("passive_dns", []):
                hostname = record.get("hostname")

                if hostname:
                    hostname = hostname.strip().lower()

                    if (
                        HOSTNAME_RE.match(hostname)
                        and (hostname == domain or hostname.endswith("." + domain))
                    ):
                        found.add(hostname)

            logger.info(f"AlienVault OTX returned {len(found)} unique subdomain(s)")

        else:
            logger.warning(f"OTX returned status {resp.status_code}")

    except Exception as e:
        logger.warning(f"OTX query failed: {e}")

    return found

def run(domain: str, resolve: bool = True) -> dict:
    logger.debug(f"Starting subdomain enumeration for {domain}")
    subdomains = set()
    subdomains |= _from_crtsh(domain)
    subdomains |= _from_otx(domain)
    subdomains.add(domain)  # include apex for completeness

    results = []
    for sub in sorted(subdomains):
        entry = {"subdomain": sub, "ip": None}
        if resolve:
            try:
                entry["ip"] = socket.gethostbyname(sub)
            except socket.gaierror:
                entry["ip"] = None
        results.append(entry)

    return {
        "module": "subdomains",
        "target": domain,
        "success": True,
        "data": {"count": len(results), "subdomains": results},
    }
