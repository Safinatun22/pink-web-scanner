"""
PINK WEB SCANNER - SCANNER ENGINE
Core HTTP scanning engine with comprehensive SSRF defense, URL validation,
redirect tracing, response streaming limits, and robots/sitemap retrieval.
"""

import socket
import ipaddress
import time
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Optional
import requests
import xml.etree.ElementTree as ET

# Allowed web ports
ALLOWED_PORTS = {80, 443, 8080, 8443}
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 (PinkWebScanner/1.0; CyberSecurityAuditor)"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB stream limit
DEFAULT_TIMEOUT = 10
MAX_REDIRECTS = 5

class SecurityViolationError(Exception):
    """Raised when SSRF or forbidden target is detected."""
    pass

def validate_and_resolve_url(url: str) -> Dict[str, Any]:
    """
    Validates URL scheme, port, and checks resolved IP against private/loopback/cloud metadata ranges.
    Returns parsed metadata and primary public IP address.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise SecurityViolationError(f"Protokol '{scheme}' tidak diizinkan. Hanya HTTP dan HTTPS yang didukung.")

    hostname = parsed.hostname
    if not hostname:
        raise SecurityViolationError("Host tidak valid atau kosong.")

    # Check for localhost / loopback names directly
    lower_host = hostname.lower()
    if lower_host in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "local"):
        raise SecurityViolationError("SSRF Protection: Pemindaian ke localhost/loopback diblokir demi keamanan.")

    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SecurityViolationError(f"Port {port} tidak diizinkan. Hanya port standar web yang didukung (80, 443, 8080, 8443).")

    # Resolve IP address to mitigate SSRF and DNS rebinding to private networks
    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"Gagal menyelesaikan domain '{hostname}': {str(e)}")

    resolved_ips = []
    for item in addr_info:
        ip_str = item[4][0]
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    primary_ip = resolved_ips[0] if resolved_ips else None

    # Check each resolved IP
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if (ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_reserved or 
                ip_obj.is_link_local or 
                ip_obj.is_multicast or 
                ip_str == "0.0.0.0"):
                raise SecurityViolationError(
                    f"SSRF Protection: Host '{hostname}' diselesaikan ke alamat IP privat/internal ({ip_str}). Pemindaian dibatalkan."
                )
        except ValueError:
            continue

    return {
        "valid_url": url,
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "primary_ip": primary_ip,
        "all_ips": resolved_ips
    }

def scan_website(
    target_url: str,
    timeout: int = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
    verify_ssl: bool = True
) -> Dict[str, Any]:
    """
    Executes a safe, in-depth HTTP scan of the target website.
    Enforces redirect validation, size limits, and measures performance metrics.
    """
    url_info = validate_and_resolve_url(target_url)
    clean_url = url_info["valid_url"]
    hostname = url_info["hostname"]
    primary_ip = url_info["primary_ip"]

    headers = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }

    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS

    start_time = time.time()
    redirect_chain = []
    
    try:
        # Stream response to enforce size limits
        response = session.get(
            clean_url,
            headers=headers,
            timeout=timeout,
            verify=verify_ssl,
            stream=True,
            allow_redirects=True
        )

        elapsed_time = round(time.time() - start_time, 4)

        # Track redirect history
        for r in response.history:
            redirect_chain.append({
                "status_code": r.status_code,
                "url": r.url,
                "headers": dict(r.headers)
            })

        # Check final redirected URL for SSRF as well
        if response.history:
            validate_and_resolve_url(response.url)

        # Read content safely up to MAX_RESPONSE_BYTES
        content_bytes = bytearray()
        for chunk in response.iter_content(chunk_size=16384):
            content_bytes.extend(chunk)
            if len(content_bytes) > MAX_RESPONSE_BYTES:
                break

        # Decode content with fallback
        encoding = response.encoding or "utf-8"
        try:
            html_text = content_bytes.decode(encoding, errors="replace")
        except Exception:
            html_text = content_bytes.decode("utf-8", errors="replace")

        resp_headers = dict(response.headers)

        return {
            "success": True,
            "url": clean_url,
            "final_url": response.url,
            "domain": hostname,
            "scheme": url_info["scheme"],
            "port": url_info["port"],
            "primary_ip": primary_ip,
            "all_ips": url_info["all_ips"],
            "status_code": response.status_code,
            "reason": response.reason,
            "response_time": elapsed_time,
            "content_size": len(content_bytes),
            "content_type": resp_headers.get("Content-Type", "Unknown"),
            "server": resp_headers.get("Server", "Undisclosed"),
            "powered_by": resp_headers.get("X-Powered-By", "Undisclosed"),
            "headers": resp_headers,
            "cookies": [c.name for c in response.cookies],
            "raw_cookies": [{"name": c.name, "secure": c.secure, "httpOnly": c.has_nonstandard_attr("HttpOnly")} for c in response.cookies],
            "redirect_count": len(response.history),
            "redirect_chain": redirect_chain,
            "html": html_text,
            "error": None
        }

    except SecurityViolationError as sve:
        return {
            "success": False,
            "url": clean_url,
            "domain": hostname,
            "status_code": 0,
            "response_time": 0.0,
            "error": str(sve)
        }
    except requests.exceptions.SSLError as ssl_err:
        return {
            "success": False,
            "url": clean_url,
            "domain": hostname,
            "status_code": 0,
            "response_time": round(time.time() - start_time, 4),
            "error": f"SSL/TLS Certificate Error: {str(ssl_err)}"
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "url": clean_url,
            "domain": hostname,
            "status_code": 0,
            "response_time": float(timeout),
            "error": f"Koneksi timeout setelah {timeout} detik."
        }
    except requests.exceptions.RequestException as req_err:
        return {
            "success": False,
            "url": clean_url,
            "domain": hostname,
            "status_code": 0,
            "response_time": round(time.time() - start_time, 4),
            "error": f"HTTP Request Error: {str(req_err)}"
        }
    except Exception as e:
        return {
            "success": False,
            "url": clean_url,
            "domain": hostname,
            "status_code": 0,
            "response_time": 0.0,
            "error": f"Scan failed: {str(e)}"
        }

def fetch_robots_txt(base_url: str, timeout: int = 5) -> Dict[str, Any]:
    """Fetches and parses robots.txt from root domain."""
    try:
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        resp = requests.get(robots_url, timeout=timeout, headers={"User-Agent": DEFAULT_USER_AGENT})
        
        sitemaps_found = []
        rules = []
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            for line in lines:
                clean_line = line.strip()
                if clean_line.lower().startswith("sitemap:"):
                    parts = clean_line.split(":", 1)
                    if len(parts) > 1:
                        sitemaps_found.append(parts[1].strip())
                elif clean_line and not clean_line.startswith("#"):
                    rules.append(clean_line)

        return {
            "url": robots_url,
            "status_code": resp.status_code,
            "exists": resp.status_code == 200,
            "content": resp.text if resp.status_code == 200 else "",
            "sitemaps": sitemaps_found,
            "rules_count": len(rules)
        }
    except Exception as e:
        return {
            "url": f"{base_url}/robots.txt",
            "status_code": 0,
            "exists": False,
            "content": f"Error fetching robots.txt: {str(e)}",
            "sitemaps": [],
            "rules_count": 0
        }

def fetch_sitemap_xml(base_url: str, sitemap_url: Optional[str] = None, timeout: int = 5) -> Dict[str, Any]:
    """Fetches and extracts URL count from sitemap.xml."""
    try:
        parsed = urlparse(base_url)
        target = sitemap_url or f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        resp = requests.get(target, timeout=timeout, headers={"User-Agent": DEFAULT_USER_AGENT})
        
        urls_found = []
        url_count = 0
        if resp.status_code == 200:
            try:
                # Basic XML parsing to extract <loc>
                root = ET.fromstring(resp.content)
                # Namespaces often used in sitemaps
                for elem in root.iter():
                    if elem.tag.endswith("loc") and elem.text:
                        urls_found.append(elem.text.strip())
                url_count = len(urls_found)
            except Exception:
                # Fallback simple line count
                url_count = resp.text.count("<loc>")

        return {
            "url": target,
            "status_code": resp.status_code,
            "exists": resp.status_code == 200,
            "url_count": url_count,
            "sample_urls": urls_found[:15],
            "raw_content": resp.text[:2000] if resp.status_code == 200 else ""
        }
    except Exception as e:
        return {
            "url": sitemap_url or f"{base_url}/sitemap.xml",
            "status_code": 0,
            "exists": False,
            "url_count": 0,
            "sample_urls": [],
            "raw_content": f"Error fetching sitemap: {str(e)}"
        }
