"""
DNS Enumeration Module
Resolves A, AAAA, MX, TXT, NS, SOA and CNAME records for the target domain.
"""
import logging

logger = logging.getLogger("recon.dns")

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]


def run(domain: str) -> dict:
    logger.debug(f"Starting DNS enumeration for {domain}")

    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        logger.error("dnspython is not installed. Run: pip install dnspython")
        return {"module": "dns", "target": domain, "success": False,
                "error": "dnspython not installed"}

    records = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata).strip() for rdata in answers]
            logger.info(f"Resolved {len(records[rtype])} {rtype} record(s) for {domain}")
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            logger.error(f"{domain} does not exist (NXDOMAIN)")
            return {"module": "dns", "target": domain, "success": False, "error": "NXDOMAIN"}
        except dns.exception.DNSException as e:
            logger.warning(f"DNS lookup error for {rtype} on {domain}: {e}")
            records[rtype] = []

    return {"module": "dns", "target": domain, "success": True, "data": records}
