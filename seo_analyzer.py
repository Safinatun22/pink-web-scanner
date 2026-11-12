"""
PINK WEB SCANNER - SEO & HTML ANALYZER
In-depth parser for Title, Meta, Headings hierarchy, Links, Images, Open Graph,
and transparent 0-100 SEO Audit scoring.
"""

from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Optional

def analyze_seo(html_text: str, current_url: str) -> Dict[str, Any]:
    """
    Performs full parsing and SEO audit on HTML content.
    Returns structured results for Title, Meta, Headings, Links, Images, and Overall Score.
    """
    if not html_text:
        return _empty_seo_result("Konten HTML kosong atau tidak dapat diunduh.")

    soup = BeautifulSoup(html_text, "html.parser")
    base_domain = urlparse(current_url).netloc.lower()

    # 1. Title Analysis
    title_tag = soup.find("title")
    title_text = title_tag.get_text(strip=True) if title_tag else ""
    title_len = len(title_text)
    
    title_status = "pass"
    title_msg = "Panjang title ideal (50 - 60 karakter)."
    if not title_text:
        title_status = "fail"
        title_msg = "Tag <title> tidak ditemukan atau kosong. Sangat krusial untuk SEO!"
    elif title_len < 30:
        title_status = "warn"
        title_msg = f"Title terlalu pendek ({title_len} karakter). Rekomendasi: 50-60 karakter agar lebih deskriptif."
    elif title_len > 65:
        title_status = "warn"
        title_msg = f"Title terlalu panjang ({title_len} karakter). Berpotensi terpotong di hasil pencarian Google."

    title_analysis = {
        "text": title_text,
        "length": title_len,
        "status": title_status,
        "recommendation": title_msg,
        "serp_preview": {
            "title": (title_text[:60] + "...") if title_len > 60 else title_text or "Tidak Ada Judul",
            "url": current_url,
            "snippet": ""
        }
    }

    # 2. Meta Tags Analysis
    meta_desc_tag = soup.find("meta", attrs={"name": lambda x: x and x.lower() == "description"})
    meta_desc = meta_desc_tag.get("content", "").strip() if meta_desc_tag else ""
    desc_len = len(meta_desc)
    title_analysis["serp_preview"]["snippet"] = (meta_desc[:155] + "...") if desc_len > 155 else meta_desc or "Tidak ada meta deskripsi."

    desc_status = "pass"
    desc_msg = "Panjang meta deskripsi optimal (120 - 160 karakter)."
    if not meta_desc:
        desc_status = "fail"
        desc_msg = "Meta description tidak ditemukan. Tambahkan untuk meningkatkan CTR di mesin pencari."
    elif desc_len < 70:
        desc_status = "warn"
        desc_msg = f"Meta description terlalu pendek ({desc_len} karakter). Tambahkan informasi relevan."
    elif desc_len > 165:
        desc_status = "warn"
        desc_msg = f"Meta description terlalu panjang ({desc_len} karakter). Mesin pencari mungkin memotong teks ini."

    meta_keywords_tag = soup.find("meta", attrs={"name": lambda x: x and x.lower() == "keywords"})
    meta_keywords = meta_keywords_tag.get("content", "").strip() if meta_keywords_tag else ""

    meta_author_tag = soup.find("meta", attrs={"name": lambda x: x and x.lower() == "author"})
    meta_author = meta_author_tag.get("content", "").strip() if meta_author_tag else ""

    meta_robots_tag = soup.find("meta", attrs={"name": lambda x: x and x.lower() == "robots"})
    meta_robots = meta_robots_tag.get("content", "").strip() if meta_robots_tag else "index, follow (default)"

    viewport_tag = soup.find("meta", attrs={"name": lambda x: x and x.lower() == "viewport"})
    has_viewport = bool(viewport_tag)
    viewport_content = viewport_tag.get("content", "").strip() if viewport_tag else ""

    canonical_tag = soup.find("link", attrs={"rel": lambda x: x and "canonical" in [r.lower() for r in (x if isinstance(x, list) else [x])]})
    canonical_url = canonical_tag.get("href", "").strip() if canonical_tag else ""

    # Open Graph & Twitter Cards
    og_data = {}
    for og_property in ["og:title", "og:description", "og:image", "og:url", "og:site_name", "og:type"]:
        tag = soup.find("meta", attrs={"property": og_property})
        if tag and tag.get("content"):
            og_data[og_property] = tag.get("content").strip()

    twitter_data = {}
    for tw_name in ["twitter:card", "twitter:title", "twitter:description", "twitter:image", "twitter:site"]:
        tag = soup.find("meta", attrs={"name": tw_name}) or soup.find("meta", attrs={"property": tw_name})
        if tag and tag.get("content"):
            twitter_data[tw_name] = tag.get("content").strip()

    meta_analysis = {
        "description": {"text": meta_desc, "length": desc_len, "status": desc_status, "recommendation": desc_msg},
        "keywords": meta_keywords,
        "author": meta_author,
        "robots": meta_robots,
        "viewport": {"present": has_viewport, "content": viewport_content},
        "canonical": canonical_url,
        "open_graph": og_data,
        "twitter_cards": twitter_data
    }

    # 3. Headings Analysis
    headings_count = {}
    headings_tree = []
    heading_tags = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
    
    for i in range(1, 7):
        headings_count[f"h{i}"] = len(soup.find_all(f"h{i}"))

    for h in heading_tags:
        lvl = int(h.name[1])
        txt = h.get_text(strip=True)
        if txt:
            headings_tree.append({"tag": h.name.upper(), "level": lvl, "text": txt[:120]})

    heading_warnings = []
    h1_count = headings_count.get("h1", 0)
    if h1_count == 0:
        heading_warnings.append("Halaman tidak memiliki tag <h1>. Sangat disarankan memiliki tepat 1 tag H1 sebagai topik utama.")
    elif h1_count > 1:
        heading_warnings.append(f"Ditemukan {h1_count} tag <h1>. Sebaiknya hanya ada 1 tag H1 per halaman untuk hierarki yang jelas.")

    # Hierarchy jump check (e.g. H1 to H3 without H2)
    prev_level = 0
    for h in headings_tree:
        curr_level = h["level"]
        if prev_level > 0 and curr_level > prev_level + 1:
            heading_warnings.append(f"Lompatan hierarki terdeteksi: {headings_tree[prev_level-1]['tag']} langsung diikuti {h['tag']} tanpa level perantara.")
            break
        prev_level = curr_level

    # 4. Links Analysis
    internal_links = []
    external_links = []
    broken_anchors = 0
    duplicate_links = set()
    seen_hrefs = set()

    for a in soup.find_all("a", href=True):
        raw_href = a.get("href", "").strip()
        anchor_text = a.get_text(strip=True)
        
        if not raw_href or raw_href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        full_url = urljoin(current_url, raw_href)
        parsed_target = urlparse(full_url)
        target_domain = parsed_target.netloc.lower()

        if full_url in seen_hrefs:
            duplicate_links.add(full_url)
        seen_hrefs.add(full_url)

        if not anchor_text:
            broken_anchors += 1

        link_obj = {
            "anchor": anchor_text or "[Tidak Ada Anchor Text]",
            "url": full_url,
            "has_anchor": bool(anchor_text)
        }

        if target_domain == base_domain or not target_domain:
            internal_links.append(link_obj)
        else:
            external_links.append(link_obj)

    links_analysis = {
        "total": len(internal_links) + len(external_links),
        "internal_count": len(internal_links),
        "external_count": len(external_links),
        "empty_anchors": broken_anchors,
        "duplicate_count": len(duplicate_links),
        "internal_samples": internal_links[:30],
        "external_samples": external_links[:30]
    }

    # 5. Image Analysis
    images = []
    missing_alt_count = 0
    missing_src_count = 0
    format_counts = {}

    for img in soup.find_all("img"):
        src = img.get("src", "").strip()
        alt = img.get("alt", "").strip()

        if not src:
            missing_src_count += 1
            continue

        if not alt:
            missing_alt_count += 1

        full_src = urljoin(current_url, src)
        # Determine format
        path_lower = urlparse(full_src).path.lower()
        fmt = "unknown"
        for ext in [".webp", ".png", ".jpg", ".jpeg", ".svg", ".gif", ".avif"]:
            if path_lower.endswith(ext):
                fmt = ext.replace(".", "")
                break
        format_counts[fmt] = format_counts.get(fmt, 0) + 1

        images.append({
            "src": full_src,
            "alt": alt,
            "has_alt": bool(alt),
            "format": fmt
        })

    image_analysis = {
        "total": len(images),
        "missing_alt": missing_alt_count,
        "missing_src": missing_src_count,
        "alt_coverage_pct": round(((len(images) - missing_alt_count) / max(len(images), 1)) * 100, 1),
        "format_distribution": format_counts,
        "samples": images[:25]
    }

    # 6. Transparent 0-100 SEO Audit Scoring Checklist
    score = 0
    checklist = []

    # Check 1: Title (15 pts)
    if title_status == "pass":
        score += 15
        checklist.append({"item": "Tag Title", "points": "15/15", "status": "pass", "note": f"Panjang optimal: {title_len} karakter."})
    elif title_status == "warn":
        score += 8
        checklist.append({"item": "Tag Title", "points": "8/15", "status": "warn", "note": title_msg})
    else:
        checklist.append({"item": "Tag Title", "points": "0/15", "status": "fail", "note": "Title tidak ditemukan atau kosong."})

    # Check 2: Meta Description (15 pts)
    if desc_status == "pass":
        score += 15
        checklist.append({"item": "Meta Description", "points": "15/15", "status": "pass", "note": f"Panjang optimal: {desc_len} karakter."})
    elif desc_status == "warn":
        score += 8
        checklist.append({"item": "Meta Description", "points": "8/15", "status": "warn", "note": desc_msg})
    else:
        checklist.append({"item": "Meta Description", "points": "0/15", "status": "fail", "note": "Meta description tidak ada."})

    # Check 3: Single H1 Tag (15 pts)
    if h1_count == 1:
        score += 15
        checklist.append({"item": "Tag H1 Tunggal", "points": "15/15", "status": "pass", "note": "Tepat terdapat 1 tag H1 utama."})
    elif h1_count > 1:
        score += 7
        checklist.append({"item": "Tag H1 Tunggal", "points": "7/15", "status": "warn", "note": f"Ditemukan {h1_count} tag H1 (sebaiknya hanya 1)."})
    else:
        checklist.append({"item": "Tag H1 Tunggal", "points": "0/15", "status": "fail", "note": "Tidak ada tag H1 sama sekali."})

    # Check 4: Heading Hierarchy Structure (10 pts)
    if not heading_warnings or (len(heading_warnings) == 1 and h1_count > 1):
        score += 10
        checklist.append({"item": "Hierarki Heading", "points": "10/10", "status": "pass", "note": "Struktur heading tertata dengan baik."})
    else:
        score += 5
        checklist.append({"item": "Hierarki Heading", "points": "5/10", "status": "warn", "note": heading_warnings[0]})

    # Check 5: Viewport Meta Tag / Mobile-friendly (10 pts)
    if has_viewport:
        score += 10
        checklist.append({"item": "Mobile Viewport", "points": "10/10", "status": "pass", "note": "Tag meta viewport terkonfigurasi untuk responsive design."})
    else:
        checklist.append({"item": "Mobile Viewport", "points": "0/10", "status": "fail", "note": "Tidak ada tag meta viewport untuk tampilan ponsel."})

    # Check 6: Canonical URL (10 pts)
    if canonical_url:
        score += 10
        checklist.append({"item": "Canonical Link", "points": "10/10", "status": "pass", "note": f"Rel canonical terpasang: {canonical_url[:50]}..."})
    else:
        score += 3
        checklist.append({"item": "Canonical Link", "points": "3/10", "status": "warn", "note": "Tag rel canonical belum disetel untuk mencegah duplikasi konten."})

    # Check 7: HTTPS Security Protocol (10 pts)
    if current_url.lower().startswith("https://"):
        score += 10
        checklist.append({"item": "Protokol HTTPS", "points": "10/10", "status": "pass", "note": "Website menggunakan protokol HTTPS terenkripsi."})
    else:
        checklist.append({"item": "Protokol HTTPS", "points": "0/10", "status": "fail", "note": "Website masih menggunakan HTTP biasa (tidak aman)."})

    # Check 8: Image ALT Coverage (10 pts)
    if len(images) == 0:
        score += 10
        checklist.append({"item": "Atribut Alt Gambar", "points": "10/10", "status": "pass", "note": "Tidak ada gambar pada halaman."})
    elif image_analysis["alt_coverage_pct"] >= 90:
        score += 10
        checklist.append({"item": "Atribut Alt Gambar", "points": "10/10", "status": "pass", "note": f"Cakupan ALT sangat baik ({image_analysis['alt_coverage_pct']}%)."})
    elif image_analysis["alt_coverage_pct"] >= 50:
        score += 5
        checklist.append({"item": "Atribut Alt Gambar", "points": "5/10", "status": "warn", "note": f"{missing_alt_count} gambar tidak memiliki atribut ALT."})
    else:
        checklist.append({"item": "Atribut Alt Gambar", "points": "0/10", "status": "fail", "note": f"Mayoritas gambar ({missing_alt_count} gambar) kehilangan ALT teks."})

    # Check 9: Open Graph / Social Tags (5 pts)
    if "og:title" in og_data or "twitter:title" in twitter_data:
        score += 5
        checklist.append({"item": "Social Media Meta", "points": "5/5", "status": "pass", "note": "Metadata Open Graph / Twitter Card terpasang."})
    else:
        score += 1
        checklist.append({"item": "Social Media Meta", "points": "1/5", "status": "warn", "note": "Open Graph dan Twitter Card belum lengkap."})

    grade = "F"
    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 50:
        grade = "D"

    return {
        "score": score,
        "grade": grade,
        "checklist": checklist,
        "title": title_analysis,
        "meta": meta_analysis,
        "headings": {
            "counts": headings_count,
            "tree": headings_tree,
            "warnings": heading_warnings
        },
        "links": links_analysis,
        "images": image_analysis,
        "disclaimer": "Skor SEO ini adalah estimasi penilaian internal algoritma Pink Web Scanner berdasarkan best-practice web standar, bukan penilaian resmi algoritma Google."
    }

def _empty_seo_result(msg: str) -> Dict[str, Any]:
    return {
        "score": 0,
        "grade": "N/A",
        "checklist": [],
        "title": {"text": "", "length": 0, "status": "fail", "recommendation": msg, "serp_preview": {"title": "", "url": "", "snippet": ""}},
        "meta": {"description": {"text": "", "length": 0, "status": "fail", "recommendation": msg}, "keywords": "", "author": "", "robots": "", "viewport": {"present": False, "content": ""}, "canonical": "", "open_graph": {}, "twitter_cards": {}},
        "headings": {"counts": {}, "tree": [], "warnings": [msg]},
        "links": {"total": 0, "internal_count": 0, "external_count": 0, "empty_anchors": 0, "duplicate_count": 0, "internal_samples": [], "external_samples": []},
        "images": {"total": 0, "missing_alt": 0, "missing_src": 0, "alt_coverage_pct": 0, "format_distribution": {}, "samples": []},
        "disclaimer": msg
    }
