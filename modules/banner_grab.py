"""
Banner Grabbing Module
Connects to a list of open ports and reads the initial service banner / response.
"""
import logging
import socket
import ssl

logger = logging.getLogger("recon.banner")

# Ports that speak plaintext HTTP and should get a HEAD request
HTTP_PORTS = {80, 8080}
# Ports that speak HTTP wrapped in TLS — need a handshake before the HEAD request
HTTPS_PORTS = {443, 8443}


def _grab_banner(domain: str, ip: str, port: int, timeout: float = 3.0) -> str:
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))

        if port in HTTPS_PORTS:
            # Wrap in TLS first (with SNI set to the domain) so the server
            # sees a real HTTPS handshake instead of garbled plaintext.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as tls_sock:
                tls_sock.sendall(
                    b"HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % domain.encode()
                )
                data = tls_sock.recv(2048)
        elif port in HTTP_PORTS:
            raw_sock.sendall(
                b"HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % domain.encode()
            )
            data = raw_sock.recv(2048)
            raw_sock.close()
        else:
            # Non-HTTP service (SSH, FTP, SMTP, etc.) — just read whatever it sends unprompted
            data = raw_sock.recv(1024)
            raw_sock.close()

        return data.decode(errors="replace").strip()
    except Exception as e:
        return f"<no banner: {e}>"


def run(domain: str, ip: str, open_ports: list) -> dict:
    logger.debug(f"Starting banner grab for {domain} ({ip}) on {len(open_ports)} ports")
    banners = {}
    for port in open_ports:
        banner = _grab_banner(domain, ip, port)
        banners[port] = banner
        logger.info(f"Banner on port {port}: {banner[:60]!r}")

    return {"module": "banner_grab", "target": domain, "success": True, "data": banners}
