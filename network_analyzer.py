"""
PINK WEB SCANNER - IP & DNS ANALYZER
Performs public DNS queries (A, AAAA, MX, NS, CNAME, TXT), reverse DNS (PTR),
and IP geolocation lookup with transparent source citation and timestamping.
"""

import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
import requests

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

def analyze_network(target_url: str) -> Dict[str, Any]:
    """
    Performs comprehensive DNS and IP network inspection.
    Returns A, AAAA, MX, NS, CNAME, TXT, Reverse DNS, and Public IP Geolocation.
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or target_url.strip()
    scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    dns_records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "CNAME": [],
        "TXT": []
    }

    # Query DNS records using dnspython if installed
    if HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        for rtype in ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]:
            try:
                answers = resolver.resolve(hostname, rtype)
                for rdata in answers:
                    if rtype == "MX":
                        dns_records["MX"].append(f"{rdata.exchange.to_text().rstrip('.')} (Prio: {rdata.preference})")
                    elif rtype in ["NS", "CNAME"]:
                        dns_records[rtype].append(rdata.target.to_text().rstrip('.'))
                    elif rtype == "TXT":
                        # Combine strings
                        txt_val = b"".join(rdata.strings).decode("utf-8", errors="replace")
                        dns_records["TXT"].append(txt_val[:160])
                    else:
                        dns_records[rtype].append(rdata.to_text())
            except Exception:
                pass
    else:
        # Fallback to standard socket
        try:
            for item in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = item[4][0]
                if ip not in dns_records["A"]:
                    dns_records["A"].append(ip)
        except Exception:
            pass

        try:
            for item in socket.getaddrinfo(hostname, None, socket.AF_INET6):
                ip6 = item[4][0]
                if ip6 not in dns_records["AAAA"]:
                    dns_records["AAAA"].append(ip6)
        except Exception:
            pass

    # Reverse DNS (PTR) on primary A record
    primary_ip = dns_records["A"][0] if dns_records["A"] else None
    ptr_record = None
    if primary_ip:
        try:
            ptr_name, _, _ = socket.gethostbyaddr(primary_ip)
            ptr_record = ptr_name
        except Exception:
            ptr_record = "Tidak tersedia / No PTR"

    # Public IP Geolocation & ASN Lookup
    geo_data = {}
    if primary_ip:
        geo_data = _fetch_ip_geo(primary_ip)

    return {
        "hostname": hostname,
        "primary_ip": primary_ip,
        "all_a_records": dns_records["A"],
        "all_aaaa_records": dns_records["AAAA"],
        "mx_records": dns_records["MX"],
        "ns_records": dns_records["NS"],
        "cname_records": dns_records["CNAME"],
        "txt_records": dns_records["TXT"],
        "ptr_record": ptr_record,
        "geolocation": geo_data,
        "timestamp": scan_timestamp,
        "source": "Public DNS Recursive Resolvers & Public IP-API Service"
    }

def _fetch_ip_geo(ip: str) -> Dict[str, Any]:
    """Queries IP geolocation and ASN data passively."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        resp = requests.get(url, timeout=3.5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": data.get("query", ip),
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", ""),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "timezone": data.get("timezone", "UTC"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "coordinates": f"{data.get('lat', 0)}, {data.get('lon', 0)}"
                }
    except Exception:
        pass
    return {
        "ip": ip,
        "country": "Informasi tidak tersedia",
        "city": "-",
        "isp": "Undisclosed",
        "asn": "-",
        "coordinates": "-"
    }
