"""
Port Scanning Module
Default: lightweight TCP-connect scan via raw sockets (no external deps).
Optional: wrap the real `nmap` binary if installed and --use-nmap is passed.
"""
import logging
import socket
import subprocess
import shutil
import re
import concurrent.futures

logger = logging.getLogger("recon.portscan")

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]


def _scan_port(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def _socket_scan(domain: str, ports: list, timeout: float, threads: int) -> dict:
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return {"module": "portscan", "target": domain, "success": False, "error": f"Could not resolve host: {e}"}

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(_scan_port, ip, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                open_ports.append(port)
                logger.info(f"Port {port} is OPEN on {ip}")

    open_ports.sort()
    return {
        "module": "portscan",
        "target": domain,
        "success": True,
        "data": {"resolved_ip": ip, "ports_scanned": len(ports), "open_ports": open_ports},
    }


def _nmap_scan(domain: str, ports: list) -> dict:
    if not shutil.which("nmap"):
        logger.warning("nmap binary not found, falling back to socket scan")
        return _socket_scan(domain, ports, timeout=1.0, threads=50)

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return {"module": "portscan", "target": domain, "success": False, "error": f"Could not resolve host: {e}"}

    port_str = ",".join(str(p) for p in ports)
    try:
        proc = subprocess.run(
            ["nmap", "-Pn", "-p", port_str, domain],
            capture_output=True, text=True, timeout=120
        )
        open_ports = []
        for line in proc.stdout.splitlines():
            # matches lines like: "80/tcp   open  http"
            match = re.match(r"^(\d+)/tcp\s+open", line.strip())
            if match:
                open_ports.append(int(match.group(1)))
        open_ports.sort()

        return {
            "module": "portscan",
            "target": domain,
            "success": True,
            "data": {
                "resolved_ip": ip,
                "ports_scanned": len(ports),
                "open_ports": open_ports,
                "raw_nmap_output": proc.stdout,  # kept for reference/debugging
            },
        }
    except Exception as e:
        logger.error(f"nmap scan failed: {e}")
        return {"module": "portscan", "target": domain, "success": False, "error": str(e)}


def run(domain: str, ports: list = None, timeout: float = 1.0, threads: int = 50, use_nmap: bool = False) -> dict:
    ports = ports or COMMON_PORTS
    logger.debug(f"Starting port scan for {domain} on {len(ports)} ports")
    if use_nmap:
        return _nmap_scan(domain, ports)
    return _socket_scan(domain, ports, timeout, threads)
