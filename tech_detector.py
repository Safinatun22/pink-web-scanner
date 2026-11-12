"""
PINK WEB SCANNER - TECHNOLOGY DETECTOR
Identifies public technology stacks (CMS, JavaScript, CSS, Analytics, Web Servers, CDNs)
using multi-layer signature heuristics with evidence matching and confidence levels.
"""

import re
from typing import Dict, Any, List

def detect_technologies(html_text: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Scans HTML content and response headers for known signatures.
    Returns categorized detections with evidence and confidence level.
    """
    detections = []
    lower_html = (html_text or "").lower()
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    server_header = lower_headers.get("server", "")
    powered_by = lower_headers.get("x-powered-by", "")

    # Helper function
    def add_tech(name: str, category: str, confidence: str, evidence: str):
        if not any(d["name"] == name for d in detections):
            detections.append({
                "name": name,
                "category": category,
                "confidence": confidence,
                "evidence": evidence
            })

    # --- 1. CMS & Platforms ---
    if "wp-content" in lower_html or "wp-includes" in lower_html or "wp-json" in lower_html:
        add_tech("WordPress", "CMS", "Tinggi", "Terdeteksi pola URL wp-content/wp-includes")
    elif 'generator" content="wordpress' in lower_html:
        add_tech("WordPress", "CMS", "Tinggi", "Meta generator WordPress terdeteksi")

    if "cdn.shopify.com" in lower_html or "shopify.theme" in lower_html:
        add_tech("Shopify", "E-Commerce", "Tinggi", "Asset Shopify CDN / Shopify.theme terdeteksi")

    if "drupal.settings" in lower_html or "sites/default/files" in lower_html:
        add_tech("Drupal", "CMS", "Tinggi", "Signature Drupal.settings ditemukan")

    if "static.parastorage.com" in lower_html or "wix.com" in lower_html:
        add_tech("Wix", "Website Builder", "Tinggi", "Wix storage domain terdeteksi")

    if "static1.squarespace.com" in lower_html:
        add_tech("Squarespace", "Website Builder", "Tinggi", "Squarespace asset domain ditemukan")

    # --- 2. JavaScript Frameworks & Libraries ---
    if "__next_data__" in lower_html or "_next/static" in lower_html:
        add_tech("Next.js", "Web Framework", "Tinggi", "Next.js __NEXT_DATA__ / _next/static terdeteksi")
        add_tech("React", "JavaScript Library", "Tinggi", "Next.js dependency")
    elif "react" in lower_html and ("reactdom" in lower_html or "react-dom" in lower_html):
        add_tech("React", "JavaScript Library", "Tinggi", "React & ReactDOM scripts terdeteksi")

    if "__nuxt__" in lower_html or "_nuxt/" in lower_html:
        add_tech("Nuxt.js", "Web Framework", "Tinggi", "Nuxt.js build assets terdeteksi")
        add_tech("Vue.js", "JavaScript Framework", "Tinggi", "Nuxt.js dependency")
    elif "data-v-" in lower_html or "v-bind" in lower_html or "vue.min.js" in lower_html:
        add_tech("Vue.js", "JavaScript Framework", "Sedang", "Atribut scope data-v- atau pustaka Vue ditemukan")

    if "ng-version" in lower_html or "ng-app" in lower_html:
        add_tech("Angular", "JavaScript Framework", "Tinggi", "Atribut ng-version / ng-app Angular terdeteksi")

    if "jquery" in lower_html and (".min.js" in lower_html or "jquery" in lower_html):
        if re.search(r"jquery[.-]?\d*.*\.js", lower_html):
            add_tech("jQuery", "JavaScript Library", "Tinggi", "Script jQuery terdeteksi")

    if "x-data=" in lower_html or "alpinejs" in lower_html:
        add_tech("Alpine.js", "JavaScript Framework", "Tinggi", "Direktif x-data Alpine.js ditemukan")

    # --- 3. CSS Frameworks ---
    if "bootstrap" in lower_html or "bootstrap.min.css" in lower_html:
        add_tech("Bootstrap", "CSS Framework", "Tinggi", "Bootstrap CSS asset terdeteksi")
    elif re.search(r'class="[^"]*(col-md-|col-lg-|navbar-expand)[^"]*"', lower_html):
        add_tech("Bootstrap", "CSS Framework", "Sedang", "Class grid Bootstrap terdeteksi")

    if "tailwind" in lower_html or re.search(r'class="[^"]*(flex flex-col|min-h-screen|grid-cols-|text-center py-)[^"]*"', lower_html):
        add_tech("Tailwind CSS", "CSS Framework", "Sedang", "Utility classes Tailwind CSS terdeteksi")

    if "bulma" in lower_html or "bulma.min.css" in lower_html:
        add_tech("Bulma", "CSS Framework", "Tinggi", "Bulma CSS terdeteksi")

    # --- 4. Analytics & Tracking ---
    if "googletagmanager.com/gtm.js" in lower_html or "gtm-" in lower_html:
        add_tech("Google Tag Manager", "Analytics", "Tinggi", "GTM container script terdeteksi")

    if "google-analytics.com" in lower_html or "gtag(" in lower_html or "analytics.js" in lower_html:
        add_tech("Google Analytics", "Analytics", "Tinggi", "Google Analytics tracking script terdeteksi")

    if "static.hotjar.com" in lower_html:
        add_tech("Hotjar", "User Tracking", "Tinggi", "Hotjar tracking script terdeteksi")

    if "connect.facebook.net" in lower_html or "fbevents.js" in lower_html:
        add_tech("Meta Pixel", "Analytics", "Tinggi", "Facebook/Meta Pixel terdeteksi")

    # --- 5. Web Servers & CDNs ---
    if "cloudflare" in server_header or "cf-ray" in lower_headers:
        add_tech("Cloudflare", "CDN / Security Proxy", "Tinggi", f"Header Server: {server_header} atau CF-Ray terdeteksi")

    if "nginx" in server_header:
        add_tech("Nginx", "Web Server", "Tinggi", f"Header Server: {server_header}")

    if "apache" in server_header:
        add_tech("Apache", "Web Server", "Tinggi", f"Header Server: {server_header}")

    if "litespeed" in server_header:
        add_tech("LiteSpeed", "Web Server", "Tinggi", f"Header Server: {server_header}")

    if "microsoft-iis" in server_header:
        add_tech("Microsoft IIS", "Web Server", "Tinggi", f"Header Server: {server_header}")

    if "cloudfront" in lower_headers.get("via", "") or "x-amz-cf-id" in lower_headers:
        add_tech("Amazon CloudFront", "CDN", "Tinggi", "Header CloudFront (Via / X-Amz-Cf-Id) terdeteksi")

    if "vercel" in server_header or "x-vercel-id" in lower_headers:
        add_tech("Vercel", "Cloud Platform", "Tinggi", "Header Vercel terdeteksi")

    if "netlify" in server_header or "x-nf-request-id" in lower_headers:
        add_tech("Netlify", "Cloud Platform", "Tinggi", "Header Netlify terdeteksi")

    if "php" in powered_by:
        add_tech("PHP", "Programming Language", "Tinggi", f"Header X-Powered-By: {powered_by}")
    elif "express" in powered_by:
        add_tech("Express.js", "Web Framework", "Tinggi", f"Header X-Powered-By: {powered_by}")
    elif "asp.net" in powered_by:
        add_tech("ASP.NET", "Web Framework", "Tinggi", f"Header X-Powered-By: {powered_by}")

    return detections
