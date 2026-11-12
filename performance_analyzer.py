"""
PINK WEB SCANNER - PERFORMANCE ANALYZER
Measures HTTP network response latency, payload transfer size, compression,
and caching configurations with actionable optimization recommendations.
"""

from typing import Dict, Any, List

def analyze_performance(scan_res: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates HTTP response performance, compression, caching headers, and redirects.
    """
    response_time = scan_res.get("response_time", 0.0)
    content_size = scan_res.get("content_size", 0)
    headers = scan_res.get("headers", {})
    lower_headers = {k.lower(): v for k, v in headers.items()}
    redirect_count = scan_res.get("redirect_count", 0)

    # Size in KB
    size_kb = round(content_size / 1024, 2)

    # Compression Check
    content_encoding = lower_headers.get("content-encoding", "none").lower()
    has_compression = any(c in content_encoding for c in ["gzip", "br", "deflate", "zstd"])

    # Cache Headers Check
    cache_control = lower_headers.get("cache-control", "")
    etag = lower_headers.get("etag", "")
    expires = lower_headers.get("expires", "")
    age = lower_headers.get("age", "")
    has_caching = bool(cache_control or etag or expires)

    # Server Timing
    server_timing = lower_headers.get("server-timing", "Tidak tersedia")

    # Score calculation (0 - 100)
    score = 100
    recommendations = []

    # Latency penalty
    if response_time > 2.5:
        score -= 30
        recommendations.append(f"Waktu respons lambat ({response_time} detik). Pertimbangkan CDN dan caching server.")
    elif response_time > 1.2:
        score -= 15
        recommendations.append(f"Waktu respons sedang ({response_time} detik). Optimalkan database query dan backend processing.")

    # Size penalty
    if size_kb > 2500:
        score -= 25
        recommendations.append(f"Ukuran dokumen HTML sangat besar ({size_kb} KB). Minifikasi HTML dan hapus skrip inline besar.")
    elif size_kb > 1000:
        score -= 10
        recommendations.append(f"Ukuran dokumen HTML cukup besar ({size_kb} KB). Pertimbangkan lazy loading dan pemisahan modul.")

    # Compression penalty
    if not has_compression:
        score -= 20
        recommendations.append("Kompresi HTTP (Gzip/Brotli) tidak aktif. Aktifkan kompresi untuk menghemat bandwidth hingga 70%.")

    # Caching penalty
    if not has_caching:
        score -= 15
        recommendations.append("Header caching (Cache-Control/ETag) tidak terdeteksi. Konfigurasikan caching browser untuk aset statis.")

    # Redirect penalty
    if redirect_count > 1:
        score -= 10 * (redirect_count - 1)
        recommendations.append(f"Terdapat {redirect_count} rantai pengalihan (redirect). Kurangi redirect berantai untuk mempercepat First Byte Time.")

    score = max(0, min(100, score))

    rating = "Bagus"
    if score >= 90:
        rating = "Sangat Cepat"
    elif score >= 75:
        rating = "Cukup Cepat"
    elif score >= 50:
        rating = "Sedang"
    else:
        rating = "Lambat"

    return {
        "score": score,
        "rating": rating,
        "response_time_sec": response_time,
        "content_size_bytes": content_size,
        "content_size_kb": size_kb,
        "compression": {
            "enabled": has_compression,
            "encoding": content_encoding
        },
        "caching": {
            "enabled": has_caching,
            "cache_control": cache_control or "Tidak disetel",
            "etag": etag or "Tidak disetel",
            "expires": expires or "Tidak disetel",
            "age": age or "Tidak disetel"
        },
        "redirect_count": redirect_count,
        "server_timing": server_timing,
        "recommendations": recommendations,
        "disclaimer": "Analisis performa ini berdasarkan metrik transfer HTTP tingkat jaringan, bukan Core Web Vitals berbasis simulasi browser penuh (LCP, FID, CLS)."
    }
