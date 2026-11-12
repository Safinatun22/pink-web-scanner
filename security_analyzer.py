"""
PINK WEB SCANNER - SECURITY ANALYZER
Inspects public security configurations: TLS/SSL certificates, HTTP security headers,
cookie hardening flags, security coverage percentage, and actionable recommendations.
Strictly passive auditing: No automated penetration testing, no exploitation.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

def analyze_security(headers: Dict[str, str], target_url: str, cookies: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Performs passive audit of SSL/TLS certificate, HTTP security headers, and cookie attributes.
    Returns comprehensive security scores, grades, and hardening recommendations.
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""
    is_https = parsed.scheme.lower() == "https"
    
    # 1. SSL/TLS Certificate Inspection
    cert_info = {"status": "none", "details": {}, "error": None}
    if is_https and hostname:
        cert_info = _inspect_ssl_certificate(hostname, parsed.port or 443)

    # Normalize header keys to lowercase
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # 2. Key Security Headers Inspection
    security_headers = [
        {
            "header": "Strict-Transport-Security",
            "key": "strict-transport-security",
            "weight": 20,
            "description": "Memaksa browser hanya berkomunikasi via enkripsi HTTPS.",
            "recommendation": "Tambahkan header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        },
        {
            "header": "Content-Security-Policy",
            "key": "content-security-policy",
            "weight": 25,
            "description": "Mencegah serangan XSS, clickjacking, dan injeksi data.",
            "recommendation": "Konfigurasikan Content-Security-Policy untuk membatasi asal sumber skrip, gaya, dan frame."
        },
        {
            "header": "X-Content-Type-Options",
            "key": "x-content-type-options",
            "weight": 15,
            "description": "Mencegah MIME-sniffing browser yang berpotensi mengeksekusi file berbahaya.",
            "recommendation": "Tambahkan header: X-Content-Type-Options: nosniff"
        },
        {
            "header": "X-Frame-Options",
            "key": "x-frame-options",
            "weight": 15,
            "description": "Melindungi situs dari serangan Clickjacking dengan melarang iframe luar.",
            "recommendation": "Tambahkan header: X-Frame-Options: SAMEORIGIN atau DENY"
        },
        {
            "header": "Referrer-Policy",
            "key": "referrer-policy",
            "weight": 15,
            "description": "Mengontrol kebocoran URL referrer saat navigasi keluar.",
            "recommendation": "Tambahkan header: Referrer-Policy: strict-origin-when-cross-origin"
        },
        {
            "header": "Permissions-Policy",
            "key": "permissions-policy",
            "weight": 10,
            "description": "Membatasi akses browser API seperti kamera, mikrofon, dan geolocation.",
            "recommendation": "Konfigurasikan Permissions-Policy (misal: camera=(), microphone=(), geolocation=())"
        }
    ]

    checked_headers = []
    earned_points = 0
    total_points = sum(h["weight"] for h in security_headers)
    present_count = 0

    for item in security_headers:
        val = lower_headers.get(item["key"])
        is_present = bool(val)
        if is_present:
            present_count += 1
            earned_points += item["weight"]
            checked_headers.append({
                "name": item["header"],
                "present": True,
                "value": val,
                "status": "pass",
                "description": item["description"],
                "advice": None
            })
        else:
            checked_headers.append({
                "name": item["header"],
                "present": False,
                "value": None,
                "status": "fail",
                "description": item["description"],
                "advice": item["recommendation"]
            })

    # Coverage calculation
    coverage_pct = round((present_count / len(security_headers)) * 100, 1)
    
    # 3. Cookie Security Audit
    cookie_audit = []
    cookie_warnings = []
    if cookies:
        for c in cookies:
            c_name = c.get("name", "Unknown")
            is_secure = c.get("secure", False)
            is_httponly = c.get("httpOnly", False)
            
            issues = []
            if not is_secure and is_https:
                issues.append("Hilang flag 'Secure'")
            if not is_httponly:
                issues.append("Hilang flag 'HttpOnly'")

            if issues:
                cookie_warnings.append(f"Cookie '{c_name}': {', '.join(issues)}")

            cookie_audit.append({
                "name": c_name,
                "secure": is_secure,
                "httponly": is_httponly,
                "safe": is_secure and is_httponly
            })

    # Additional points for HTTPS and valid SSL
    base_security_score = earned_points
    if not is_https:
        base_security_score = min(base_security_score, 30)

    # Grade calculation
    grade = "F"
    if base_security_score >= 90:
        grade = "A+"
    elif base_security_score >= 80:
        grade = "A"
    elif base_security_score >= 70:
        grade = "B"
    elif base_security_score >= 50:
        grade = "C"
    elif base_security_score >= 35:
        grade = "D"

    # Actionable hardening checklist
    recommendations = []
    if not is_https:
        recommendations.append("Prioritas Tinggi: Pasang sertifikat SSL/TLS dan alihkan semua lalu lintas HTTP ke HTTPS.")
    for h in checked_headers:
        if not h["present"]:
            recommendations.append(f"Header Keamanan: {h['advice']}")
    if cookie_warnings:
        recommendations.append("Cookie Hardening: Tambahkan atribut Secure dan HttpOnly pada semua session cookie.")

    return {
        "score": base_security_score,
        "grade": grade,
        "coverage_pct": coverage_pct,
        "present_headers_count": present_count,
        "total_headers_checked": len(security_headers),
        "headers": checked_headers,
        "ssl_certificate": cert_info,
        "cookies": {
            "total": len(cookies) if cookies else 0,
            "audit": cookie_audit,
            "warnings": cookie_warnings
        },
        "recommendations": recommendations,
        "disclaimer": "Pink Web Scanner hanya melakukan audit konfigurasi publik pasif dan tidak melakukan pengujian penetrasi agresif atau eksploitasi."
    }

def _inspect_ssl_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Retrieves and parses SSL/TLS certificate metadata via socket."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Parse dates
                # Format: 'May 15 12:00:00 2024 GMT'
                date_fmt = r"%b %d %H:%M:%S %Y %Z"
                not_before = datetime.strptime(cert["notBefore"], date_fmt).replace(tzinfo=timezone.utc)
                not_after = datetime.strptime(cert["notAfter"], date_fmt).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)

                days_remaining = (not_after - now).days
                is_expired = days_remaining < 0

                # Extract Issuer & Subject
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]

                status_label = "Valid"
                if is_expired:
                    status_label = "Expired (Kedaluwarsa)"
                elif days_remaining < 30:
                    status_label = f"Expiring Soon ({days_remaining} hari lagi)"

                return {
                    "status": "valid" if not is_expired else "expired",
                    "status_label": status_label,
                    "common_name": subject.get("commonName", hostname),
                    "issuer_name": issuer.get("organizationName") or issuer.get("commonName", "Unknown Issuer"),
                    "valid_from": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "valid_to": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "days_remaining": days_remaining,
                    "sans": sans[:10],
                    "tls_version": version,
                    "cipher_suite": cipher[0] if cipher else "Unknown",
                    "bits": cipher[2] if cipher else 0,
                    "error": None
                }
    except Exception as e:
        return {
            "status": "error",
            "status_label": "Gagal Mengambil Sertifikat",
            "error": str(e)
        }
