"""
Technology Detection Module
Lightweight fingerprinting of web technologies via HTTP headers and HTML
markers, no external paid API needed. Falls back gracefully if the host
doesn't serve HTTP/HTTPS.
"""
import logging
import re
import requests

logger = logging.getLogger("recon.techdetect")

HEADERS = {"User-Agent": "recon-tool/1.0 (educational/internship use)"}

# A small set of well-known signatures. Not exhaustive — intended to
# demonstrate the technique, similar in spirit to WhatWeb/Wappalyzer.
SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes"],
    "Drupal": [r"Drupal.settings", r"/sites/default/files"],
    "Joomla": [r"/media/jui/", r"Joomla!"],
    "Shopify": [r"shopify"],
    "Nginx": [r"nginx"],
    "Apache": [r"Apache"],
    "Microsoft IIS": [r"microsoft-iis"],
    "PHP": [r"\.php", r"PHPSESSID"],
    "Express.js": [r"express"],
    "ASP.NET": [r"asp\.net"],
    "Cloudflare": [r"cloudflare"],
    "React": [r"__REACT_DEVTOOLS", r"react-dom"],
    "Next.js": [r"__next"],
    "jQuery": [r"jquery"],
    "Bootstrap": [r"bootstrap"],
    "Laravel": [r"laravel_session"],
    "Java / JSP": [r"JSESSIONID"],
}


def _check_signatures(headers: dict, body: str, cookies: dict) -> list:
    """Match known technology signatures against headers, body and cookies."""
    cookie_names = " ".join(cookies.keys())
    haystack = " ".join(f"{k}:{v}" for k, v in headers.items()) + " " + body + " " + cookie_names
    matched = []
    for tech, patterns in SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, haystack, re.IGNORECASE):
                matched.append(tech)
                break
    return matched


def run(domain: str) -> dict:
    logger.debug(f"Starting technology detection for {domain}")
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
            tech = _check_signatures(dict(resp.headers), resp.text[:20000], resp.cookies.get_dict())
            result = {
                "url": resp.url,
                "status_code": resp.status_code,
                "server_header": resp.headers.get("Server"),
                "powered_by": resp.headers.get("X-Powered-By"),
                "detected_technologies": tech,
            }
            logger.info(f"Tech detection succeeded via {scheme.upper()}: {tech}")
            return {"module": "tech_detect", "target": domain, "success": True, "data": result}
        except Exception as e:
            logger.warning(f"{scheme.upper()} request failed for {domain}: {e}")
            continue

    return {"module": "tech_detect", "target": domain, "success": False, "error": "No HTTP/HTTPS response"}
