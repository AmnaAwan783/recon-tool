"""
Report Generator
Builds a .txt or .html summary report from the collected recon results.
Each module gets a dedicated formatter so the output reads like a real
engagement report instead of a raw JSON dump.
"""
import logging
from datetime import datetime, timezone

logger = logging.getLogger("recon.report")

TITLES = {
    "whois": "WHOIS Lookup",
    "dns": "DNS Enumeration",
    "subdomains": "Subdomain Enumeration",
    "portscan": "Port Scan",
    "banner_grab": "Banner Grabbing",
    "tech_detect": "Technology Detection",
}

MODULE_ORDER = ["whois", "dns", "subdomains", "portscan", "banner_grab", "tech_detect"]


# --------------------------------------------------------------------------
# Per-module TEXT formatters — each returns a list of plain-text lines
# --------------------------------------------------------------------------

def _fmt_whois_txt(data: dict) -> list:
    rows = [
        ("Domain", data.get("domain_name")),
        ("Registrar", data.get("registrar")),
        ("Organization", data.get("org")),
        ("Country", data.get("country")),
        ("Created", data.get("creation_date")),
        ("Expires", data.get("expiration_date")),
        ("Updated", data.get("updated_date")),
    ]
    lines = [f"  {label:<14}: {value}" for label, value in rows if value]

    name_servers = data.get("name_servers") or []
    if isinstance(name_servers, str):
        name_servers = [name_servers]
    if name_servers:
        lines.append(f"  {'Name Servers':<14}: {name_servers[0]}")
        lines += [f"  {'':<14}  {ns}" for ns in name_servers[1:]]

    status = data.get("status") or []
    if isinstance(status, str):
        status = [status]
    if status:
        lines.append(f"  {'Status':<14}: {status[0]}")
        lines += [f"  {'':<14}  {s}" for s in status[1:]]

    emails = data.get("emails")
    if emails:
        lines.append(f"  {'Abuse Email':<14}: {emails}")

    return lines or ["  No WHOIS data returned."]


def _fmt_dns_txt(data: dict) -> list:
    lines = []
    order = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]
    for rtype in order:
        values = data.get(rtype) or []
        if not values:
            continue
        lines.append(f"  {rtype} records ({len(values)}):")
        for v in values:
            lines.append(f"    - {v}")
    return lines or ["  No DNS records found."]


def _fmt_subdomains_txt(data: dict) -> list:
    subs = data.get("subdomains", [])
    lines = [f"  Total found: {data.get('count', len(subs))}", ""]
    for entry in subs:
        ip = entry.get("ip") or "unresolved"
        lines.append(f"  {entry['subdomain']:<40} -> {ip}")
    return lines


def _fmt_portscan_txt(data: dict) -> list:
    open_ports = data.get("open_ports", [])
    lines = [
        f"  Resolved IP    : {data.get('resolved_ip')}",
        f"  Ports scanned  : {data.get('ports_scanned')}",
        f"  Open ports     : {len(open_ports)}",
        "",
    ]
    if open_ports:
        for p in open_ports:
            lines.append(f"    - {p}/tcp  open")
    else:
        lines.append("    (none open)")

    if "raw_nmap_output" in data:
        lines.append("")
        lines.append("  --- raw nmap output ---")
        lines.extend(f"  {l}" for l in data["raw_nmap_output"].splitlines())

    return lines


def _fmt_banner_txt(data: dict) -> list:
    lines = []
    for port, banner in data.items():
        lines.append(f"  Port {port}:")
        if banner.startswith("<no banner"):
            lines.append(f"    {banner}")
        else:
            banner_lines = banner.replace("\r\n", "\n").split("\n")
            lines.append(f"    Status : {banner_lines[0]}")
            for hl in banner_lines[1:6]:
                if hl.strip():
                    lines.append(f"    {hl.strip()}")
            if len(banner_lines) > 6:
                lines.append(f"    ... ({len(banner_lines) - 6} more header line(s) truncated)")
        lines.append("")
    return lines


def _fmt_tech_txt(data: dict) -> list:
    tech = data.get("detected_technologies") or []
    lines = [
        f"  URL            : {data.get('url')}",
        f"  Status code    : {data.get('status_code')}",
        f"  Server header  : {data.get('server_header') or '-'}",
        f"  X-Powered-By   : {data.get('powered_by') or '-'}",
        f"  Technologies   : {', '.join(tech) if tech else 'None detected'}",
    ]
    return lines


TXT_FORMATTERS = {
    "whois": _fmt_whois_txt,
    "dns": _fmt_dns_txt,
    "subdomains": _fmt_subdomains_txt,
    "portscan": _fmt_portscan_txt,
    "banner_grab": _fmt_banner_txt,
    "tech_detect": _fmt_tech_txt,
}


def generate_txt(domain: str, results: dict) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "=" * 72,
        "  RECONNAISSANCE REPORT".ljust(71),
        "=" * 72,
        f"  Target     : {domain}",
        f"  Generated  : {timestamp}",
        "=" * 72,
        "",
    ]

    for key in MODULE_ORDER:
        if key not in results:
            continue
        result = results[key]
        title = TITLES[key]
        lines.append(f"[{title}]")
        lines.append("-" * (len(title) + 2))
        if not result.get("success", False):
            lines.append(f"  FAILED: {result.get('error', 'unknown error')}")
        else:
            formatter = TXT_FORMATTERS.get(key)
            lines.extend(formatter(result.get("data", {})) if formatter else ["  (no formatter)"])
        lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------
# Per-module HTML formatters — each returns an HTML fragment string
# --------------------------------------------------------------------------

def _kv_table(rows: list) -> str:
    body = "".join(
        f"<tr><th>{label}</th><td>{value}</td></tr>"
        for label, value in rows if value not in (None, "", [])
    )
    return f"<table>{body}</table>" if body else "<p class='muted'>No data.</p>"


def _fmt_whois_html(data: dict) -> str:
    ns = data.get("name_servers") or []
    status = data.get("status") or []
    rows = [
        ("Domain", data.get("domain_name")),
        ("Registrar", data.get("registrar")),
        ("Organization", data.get("org")),
        ("Country", data.get("country")),
        ("Created", data.get("creation_date")),
        ("Expires", data.get("expiration_date")),
        ("Updated", data.get("updated_date")),
        ("Name Servers", "<br>".join(ns) if isinstance(ns, list) else ns),
        ("Status", "<br>".join(status) if isinstance(status, list) else status),
        ("Abuse Email", data.get("emails")),
    ]
    return _kv_table(rows)


def _fmt_dns_html(data: dict) -> str:
    order = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]
    rows = []
    for rtype in order:
        values = data.get(rtype) or []
        if values:
            rows.append((rtype, "<br>".join(values)))
    return _kv_table(rows)


def _fmt_subdomains_html(data: dict) -> str:
    subs = data.get("subdomains", [])
    if not subs:
        return "<p class='muted'>No subdomains found.</p>"
    body = "".join(
        f"<tr><td>{e['subdomain']}</td><td>{e.get('ip') or 'unresolved'}</td></tr>" for e in subs
    )
    return (
        f"<p class='muted'>Total found: {data.get('count', len(subs))}</p>"
        f"<table><tr><th>Subdomain</th><th>Resolved IP</th></tr>{body}</table>"
    )


def _fmt_portscan_html(data: dict) -> str:
    open_ports = data.get("open_ports", [])
    summary = _kv_table([
        ("Resolved IP", data.get("resolved_ip")),
        ("Ports scanned", data.get("ports_scanned")),
        ("Open ports", len(open_ports)),
    ])
    if open_ports:
        rows = "".join(f"<tr><td>{p}</td><td>open</td></tr>" for p in open_ports)
        ports_table = f"<table><tr><th>Port</th><th>State</th></tr>{rows}</table>"
    else:
        ports_table = "<p class='muted'>No open ports found.</p>"

    raw_block = ""
    if "raw_nmap_output" in data:
        raw_block = f"<details><summary>Raw nmap output</summary><pre>{data['raw_nmap_output']}</pre></details>"

    return summary + ports_table + raw_block


def _fmt_banner_html(data: dict) -> str:
    html = ""
    for port, banner in data.items():
        html += f"<h3 class='port-h'>Port {port}</h3>"
        if banner.startswith("<no banner"):
            html += f"<p class='muted'>{banner}</p>"
        else:
            html += f"<pre>{banner.replace(chr(13), '')}</pre>"
    return html


def _fmt_tech_html(data: dict) -> str:
    tech = data.get("detected_technologies") or []
    rows = [
        ("URL", data.get("url")),
        ("Status code", data.get("status_code")),
        ("Server header", data.get("server_header")),
        ("X-Powered-By", data.get("powered_by")),
        ("Technologies", ", ".join(tech) if tech else "None detected"),
    ]
    return _kv_table(rows)


HTML_FORMATTERS = {
    "whois": _fmt_whois_html,
    "dns": _fmt_dns_html,
    "subdomains": _fmt_subdomains_html,
    "portscan": _fmt_portscan_html,
    "banner_grab": _fmt_banner_html,
    "tech_detect": _fmt_tech_html,
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report — {domain}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 0; padding: 40px;
          background: #0f1117; color: #e6e6e6; line-height: 1.5; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ border-bottom: 2px solid #3a86ff; padding-bottom: 8px; margin-bottom: 4px; }}
  h2 {{ color: #3a86ff; margin-top: 36px; font-size: 1.15em; border-left: 4px solid #3a86ff;
        padding-left: 10px; }}
  h3.port-h {{ color: #9aa0ac; margin: 16px 0 4px; font-size: 0.95em; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
  th, td {{ border: 1px solid #2a2d3a; padding: 6px 10px; text-align: left; vertical-align: top;
            font-size: 0.92em; }}
  th {{ background: #1a1d29; width: 180px; white-space: nowrap; }}
  .meta {{ color: #9aa0ac; font-size: 0.9em; margin-bottom: 12px; }}
  .error {{ color: #ff6b6b; }}
  .muted {{ color: #6b7280; font-style: italic; margin: 6px 0; }}
  pre {{ background: #1a1d29; padding: 10px 14px; overflow-x: auto; border-radius: 4px;
         font-size: 0.85em; white-space: pre-wrap; word-break: break-word; }}
  .section {{ margin-bottom: 8px; }}
</style>
</head>
<body>
<div class="container">
<h1>Reconnaissance Report</h1>
<p class="meta">Target: <strong>{domain}</strong> &nbsp;|&nbsp; Generated: {timestamp}</p>
{sections}
</div>
</body>
</html>
"""


def generate_html(domain: str, results: dict) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sections = ""
    for key in MODULE_ORDER:
        if key not in results:
            continue
        result = results[key]
        title = TITLES[key]
        sections += f"<div class='section'><h2>{title}</h2>"
        if not result.get("success", False):
            sections += f"<p class='error'>Failed: {result.get('error', 'unknown error')}</p>"
        else:
            formatter = HTML_FORMATTERS.get(key)
            sections += formatter(result.get("data", {})) if formatter else "<p>(no formatter)</p>"
        sections += "</div>"

    return HTML_TEMPLATE.format(domain=domain, timestamp=timestamp, sections=sections)


def write_report(domain: str, results: dict, output_path: str, fmt: str = "txt"):
    if fmt == "html":
        content = generate_html(domain, results)
    else:
        content = generate_txt(domain, results)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    logger.info(f"Report written to {output_path}")
    return output_path
