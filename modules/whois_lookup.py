"""
WHOIS Lookup Module
Performs a passive WHOIS query against a target domain.
"""
import logging

logger = logging.getLogger("recon.whois")


def run(domain: str) -> dict:
    """
    Perform a WHOIS lookup for the given domain.

    Returns a dict suitable for the report generator. Never raises;
    on failure it returns an 'error' key so the rest of the scan can continue.
    """
    logger.debug(f"Starting WHOIS lookup for {domain}")
    try:
        import whois  # python-whois
        data = whois.whois(domain)

        result = {
            "domain_name": _flatten(data.get("domain_name")),
            "registrar": data.get("registrar"),
            "creation_date": _flatten(data.get("creation_date")),
            "expiration_date": _flatten(data.get("expiration_date")),
            "updated_date": _flatten(data.get("updated_date")),
            "name_servers": data.get("name_servers"),
            "status": data.get("status"),
            "emails": data.get("emails"),
            "org": data.get("org"),
            "country": data.get("country"),
        }
        logger.info(f"WHOIS lookup successful for {domain}")
        return {"module": "whois", "target": domain, "success": True, "data": result}

    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        return {"module": "whois", "target": domain, "success": False, "error": str(e)}


def _flatten(value):
    """WHOIS fields sometimes return lists of duplicate values; normalize to a single value/str."""
    if isinstance(value, list):
        # dedupe preserving order, stringify dates etc.
        seen = []
        for v in value:
            sv = str(v)
            if sv not in seen:
                seen.append(sv)
        return seen if len(seen) > 1 else (seen[0] if seen else None)
    return str(value) if value is not None else None
