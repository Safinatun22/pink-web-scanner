"""
PINK WEB SCANNER - MAIN STREAMLIT APPLICATION
Futuristic Cyber Security Website Analysis Platform
Tagline: DISCOVER • ANALYZE • PROTECT • UNDERSTAND
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional

# Import Modular Engines
from styles import get_custom_css
import database as db
import scanner
import seo_analyzer
import security_analyzer
import network_analyzer
import performance_analyzer
import tech_detector
import report_generator

# Page Configuration
st.set_page_config(
    page_title="Pink Web Scanner | Cyber Security Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Database
db.init_db()

# Session State Initialization
if "current_scan" not in st.session_state:
    st.session_state.current_scan = None
if "theme" not in st.session_state:
    st.session_state.theme = db.get_setting("theme", "dark")
if "lang" not in st.session_state:
    st.session_state.lang = db.get_setting("lang", "id")
if "timeout" not in st.session_state:
    st.session_state.timeout = int(db.get_setting("timeout", "10"))
if "verify_ssl" not in st.session_state:
    st.session_state.verify_ssl = db.get_setting("verify_ssl", "True") == "True"
if "user_agent_choice" not in st.session_state:
    st.session_state.user_agent_choice = db.get_setting("user_agent_choice", "PinkWebScanner Default")

# Translations Dictionary
TRANSLATIONS = {
    "id": {
        "nav_overview": "Overview Dashboard",
        "nav_scanner": "Website Scanner",
        "nav_title": "Title Detector",
        "nav_meta": "Meta Analyzer",
        "nav_headings": "Heading Analyzer",
        "nav_links": "Link Analyzer",
        "nav_images": "Image Analyzer",
        "nav_seo": "SEO Audit",
        "nav_security": "Security Analyzer",
        "nav_network": "IP & DNS Analyzer",
        "nav_tech": "Technology Detector",
        "nav_perf": "Performance Analyzer",
        "nav_robots": "Robots & Sitemap",
        "nav_history": "Scan History",
        "nav_report": "Report Center",
        "nav_compare": "Comparison Tool",
        "nav_learn": "Learning Center",
        "nav_settings": "Settings",
        "tagline": "DISCOVER • ANALYZE • PROTECT • UNDERSTAND",
        "no_scan_title": "Belum Ada Website yang Dipindai",
        "no_scan_desc": "Masukkan URL di menu Website Scanner atau gunakan Quick Scan untuk memulai audit menyeluruh.",
        "btn_start_scan": "Mulai Pemindaian",
        "btn_quick_scan": "Quick Scan",
        "url_placeholder": "https://example.com atau example.com",
    },
    "en": {
        "nav_overview": "Overview Dashboard",
        "nav_scanner": "Website Scanner",
        "nav_title": "Title Detector",
        "nav_meta": "Meta Analyzer",
        "nav_headings": "Heading Analyzer",
        "nav_links": "Link Analyzer",
        "nav_images": "Image Analyzer",
        "nav_seo": "SEO Audit",
        "nav_security": "Security Analyzer",
        "nav_network": "IP & DNS Analyzer",
        "nav_tech": "Technology Detector",
        "nav_perf": "Performance Analyzer",
        "nav_robots": "Robots & Sitemap",
        "nav_history": "Scan History",
        "nav_report": "Report Center",
        "nav_compare": "Comparison Tool",
        "nav_learn": "Learning Center",
        "nav_settings": "Settings",
        "tagline": "DISCOVER • ANALYZE • PROTECT • UNDERSTAND",
        "no_scan_title": "No Scanned Website Active",
        "no_scan_desc": "Enter a target URL in Website Scanner or run Quick Scan to begin complete audit.",
        "btn_start_scan": "Start Scanning",
        "btn_quick_scan": "Quick Scan",
        "url_placeholder": "https://example.com or example.com",
    }
}

t = TRANSLATIONS.get(st.session_state.lang, TRANSLATIONS["id"])

# Inject Custom Cyber Styles
st.markdown(get_custom_css(st.session_state.theme), unsafe_allow_html=True)

# Helper Scan Execution Function
def run_full_scan(target_url: str) -> Optional[Dict[str, Any]]:
    """Runs all analysis modules and persists results to SQLite."""
    if not target_url.strip():
        st.error("Silakan masukkan URL website yang valid.")
        return None

    progress_bar = st.progress(5, text="🔒 Memvalidasi URL & Mengaktifkan SSRF Shield...")
    time.sleep(0.1)

    # 1. Network & HTTP Scan
    progress_bar.progress(20, text="🌐 Mengirim Probe HTTP & Mengukur Latensi...")
    raw_scan = scanner.scan_website(
        target_url=target_url,
        timeout=st.session_state.timeout,
        verify_ssl=st.session_state.verify_ssl
    )

    if not raw_scan.get("success"):
        progress_bar.empty()
        st.error(f"❌ Pemindaian Gagal: {raw_scan.get('error')}")
        return None

    # 2. SEO & HTML Analysis
    progress_bar.progress(40, text="📄 Membedah HTML, Title, Meta, Headings, Link & Gambar...")
    seo_res = seo_analyzer.analyze_seo(raw_scan.get("html", ""), raw_scan.get("final_url", target_url))

    # 3. Security Analysis
    progress_bar.progress(60, text="🛡️ Menganalisis Sertifikat SSL/TLS & Security Headers...")
    sec_res = security_analyzer.analyze_security(
        headers=raw_scan.get("headers", {}),
        target_url=raw_scan.get("final_url", target_url),
        cookies=raw_scan.get("raw_cookies", [])
    )

    # 4. Network & DNS Analysis
    progress_bar.progress(75, text="📡 Mengambil DNS Records (A, AAAA, MX, NS) & Geolocation...")
    net_res = network_analyzer.analyze_network(raw_scan.get("final_url", target_url))

    # 5. Performance Evaluation
    progress_bar.progress(85, text="⚡ Mengevaluasi Caching, Kompresi, dan Kecepatan...")
    perf_res = performance_analyzer.analyze_performance(raw_scan)

    # 6. Technology Stack Detector
    progress_bar.progress(92, text="🔍 Mencocokkan Heuristic Signature Teknologi (CMS, JS, CDN)...")
    tech_stack = tech_detector.detect_technologies(raw_scan.get("html", ""), raw_scan.get("headers", {}))

    # 7. Robots & Sitemap
    robots_res = scanner.fetch_robots_txt(raw_scan.get("final_url", target_url))
    sitemap_res = scanner.fetch_sitemap_xml(raw_scan.get("final_url", target_url))

    progress_bar.progress(98, text="💾 Menyimpan Hasil ke Database SQLite...")
    
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    full_payload = {
        "scan_id": scan_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": raw_scan.get("url"),
        "final_url": raw_scan.get("final_url"),
        "domain": raw_scan.get("domain"),
        "status_code": raw_scan.get("status_code"),
        "reason": raw_scan.get("reason"),
        "primary_ip": raw_scan.get("primary_ip"),
        "response_time": raw_scan.get("response_time"),
        "content_size": raw_scan.get("content_size"),
        "content_type": raw_scan.get("content_type"),
        "server": raw_scan.get("server"),
        "powered_by": raw_scan.get("powered_by"),
        "headers": raw_scan.get("headers"),
        "cookies": raw_scan.get("cookies"),
        "redirect_count": raw_scan.get("redirect_count"),
        "redirect_chain": raw_scan.get("redirect_chain"),
        "seo_score": seo_res.get("score", 0),
        "seo_grade": seo_res.get("grade", "N/A"),
        "security_coverage": sec_res.get("coverage_pct", 0.0),
        "security_score": sec_res.get("score", 0),
        "seo": seo_res,
        "security": sec_res,
        "network": net_res,
        "performance": perf_res,
        "tech_stack": tech_stack,
        "robots": robots_res,
        "sitemap": sitemap_res
    }

    # Save to SQLite
    db.save_scan(full_payload)
    st.session_state.current_scan = full_payload

    progress_bar.progress(100, text="✨ Pemindaian Selesai!")
    time.sleep(0.3)
    progress_bar.empty()
    st.toast("🎉 Pemindaian Berhasil Diselesaikan!", icon="🛡️")
    return full_payload

# SIDEBAR PERMANEN
with st.sidebar:
    # Logo & App Title
    st.markdown("""
        <div style="text-align: center; padding: 10px 0 20px 0;">
            <div style="font-size: 2.8rem; filter: drop-shadow(0 0 10px #FF4FA3);">🛡️</div>
            <h2 style="margin: 4px 0 0 0; font-size: 1.4rem; font-weight: 800; background: linear-gradient(90deg, #FFFFFF, #FF69B4, #FF4FA3); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">PINK WEB SCANNER</h2>
            <div style="font-size: 0.75rem; letter-spacing: 1.5px; color: #FF69B4; font-weight: 600;">DISCOVER • ANALYZE • PROTECT</div>
        </div>
    """, unsafe_allow_html=True)

    # Active Scan Indicator
    if st.session_state.current_scan:
        curr = st.session_state.current_scan
        st.markdown(f"""
            <div style="background: rgba(255, 79, 163, 0.12); border: 1px solid rgba(255, 79, 163, 0.4); border-radius: 10px; padding: 10px; margin-bottom: 14px;">
                <div style="font-size: 0.72rem; color: #FF69B4; font-weight: 600; text-transform: uppercase;">Target Aktif</div>
                <div style="font-size: 0.88rem; font-weight: 700; color: #FFFFFF; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{curr.get('domain')}</div>
                <div style="font-size: 0.75rem; color: #C7A6BA;">Status: <span style="color: #4ade80; font-weight: 600;">{curr.get('status_code')} OK</span> | {curr.get('response_time')}s</div>
            </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
            <div style="background: rgba(255, 255, 255, 0.05); border: 1px dashed rgba(255, 79, 163, 0.3); border-radius: 10px; padding: 10px; margin-bottom: 14px; text-align: center;">
                <span style="font-size: 0.78rem; color: #C7A6BA;">Belum ada target aktif</span>
            </div>
        """, unsafe_allow_html=True)

    # Main Navigation
    menu_options = [
        t["nav_overview"],
        t["nav_scanner"],
        t["nav_title"],
        t["nav_meta"],
        t["nav_headings"],
        t["nav_links"],
        t["nav_images"],
        t["nav_seo"],
        t["nav_security"],
        t["nav_network"],
        t["nav_tech"],
        t["nav_perf"],
        t["nav_robots"],
        t["nav_history"],
        t["nav_report"],
        t["nav_compare"],
        t["nav_learn"],
        t["nav_settings"]
    ]

    selected_menu = st.radio("NAVIGASI UTAMA", menu_options, label_visibility="collapsed")

    st.markdown("---")

    # Quick Scanner Controls in Sidebar
    col_th1, col_th2 = st.columns(2)
    with col_th1:
        new_theme = st.selectbox("🎨 Tema", ["Dark", "Light"], index=0 if st.session_state.theme == "dark" else 1)
        if (new_theme.lower() != st.session_state.theme):
            st.session_state.theme = new_theme.lower()
            db.save_setting("theme", st.session_state.theme)
            st.rerun()

    with col_th2:
        new_lang = st.selectbox("🌐 Bahasa", ["ID", "EN"], index=0 if st.session_state.lang == "id" else 1)
        if (new_lang.lower() != st.session_state.lang):
            st.session_state.lang = new_lang.lower()
            db.save_setting("lang", st.session_state.lang)
            st.rerun()

    # User Profile & Version Footer
    st.markdown("""
        <div style="font-size: 0.75rem; color: #C7A6BA; margin-top: 15px; text-align: center;">
            <div>Pink Web Scanner v1.0.0 Pro</div>
            <div style="color: #FF69B4;">● Cyber Engine Ready</div>
        </div>
    """, unsafe_allow_html=True)


# RENDER BREADCRUMB & HEADER HELPER
def render_header(title: str, subtitle: str = ""):
    st.markdown(f"""
        <div class="breadcrumb">
            <span>Pink Web Scanner</span> &gt; <span class="active">{title}</span>
        </div>
        <div class="cyber-banner">
            <h1 class="cyber-title">🛡️ {title}</h1>
            <div class="cyber-subtitle">{subtitle or t['tagline']}</div>
        </div>
    """, unsafe_allow_html=True)


# ==========================================
# 1. OVERVIEW DASHBOARD
# ==========================================
if selected_menu == t["nav_overview"]:
    render_header(t["nav_overview"], "Executive Summary & Real-Time Scanning Analytics")

    stats = db.get_overview_stats()

    # Top KPI Stat Cards
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1:
        st.markdown(f"""
            <div class="stat-card">
                <div class="stat-label">Total Dipindai</div>
                <div class="stat-value">{stats['total_scans']}</div>
                <span class="stat-badge">Website</span>
            </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
            <div class="stat-card">
                <div class="stat-label">Scan Berhasil</div>
                <div class="stat-value" style="color: #4ade80;">{stats['success_scans']}</div>
                <span class="stat-badge">HTTP 2xx/3xx</span>
            </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
            <div class="stat-card">
                <div class="stat-label">Scan Gagal</div>
                <div class="stat-value" style="color: #f87171;">{stats['failed_scans']}</div>
                <span class="stat-badge">Error/Timeout</span>
            </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
            <div class="stat-card">
                <div class="stat-label">Rata-rata SEO</div>
                <div class="stat-value">{stats['avg_seo']}<span style="font-size: 1rem;">/100</span></div>
                <span class="stat-badge">Audit Score</span>
            </div>
        """, unsafe_allow_html=True)
    with c5:
        st.markdown(f"""
            <div class="stat-card">
                <div class="stat-label">Avg Latency</div>
                <div class="stat-value">{stats['avg_resp_time']}s</div>
                <span class="stat-badge">Response</span>
            </div>
        """, unsafe_allow_html=True)
    with c6:
        st.markdown(f"""
            <div class="stat-card">
                <div class="stat-label">Avg Security</div>
                <div class="stat-value">{stats['avg_sec_coverage']}%</div>
                <span class="stat-badge">Headers</span>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Quick Scan Bar
    with st.container():
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("⚡ Quick Scan Target")
        qcol1, qcol2 = st.columns([4, 1])
        with qcol1:
            quick_url = st.text_input("Quick URL Target", placeholder=t["url_placeholder"], label_visibility="collapsed")
        with qcol2:
            if st.button("🚀 Pindai Sekarang", use_container_width=True):
                if quick_url:
                    run_full_scan(quick_url)
                    st.rerun()
                else:
                    st.warning("Masukkan URL terlebih dahulu.")
        st.markdown('</div>', unsafe_allow_html=True)

    # Activity & Status Distribution Charts
    col_chart1, col_chart2 = st.columns([3, 2])
    with col_chart1:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("📈 Aktivitas Pemindaian Terakhir")
        daily_data = stats.get("daily_activity", [])
        if daily_data:
            df_act = pd.DataFrame(daily_data)
            fig_act = px.bar(
                df_act, x="date", y="count",
                labels={"date": "Tanggal", "count": "Jumlah Pemindaian"},
                color_discrete_sequence=["#FF4FA3"]
            )
            fig_act.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#FFFFFF" if st.session_state.theme == "dark" else "#2B1130",
                margin=dict(l=20, r=20, t=20, b=20)
            )
            st.plotly_chart(fig_act, use_container_width=True)
        else:
            st.info("Belum ada data aktivitas scan.")
        st.markdown('</div>', unsafe_allow_html=True)

    with col_chart2:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("🎯 Distribusi Status HTTP")
        dist_data = stats.get("status_distribution", [])
        if dist_data:
            df_dist = pd.DataFrame(dist_data)
            fig_dist = px.pie(
                df_dist, names="status", values="count",
                hole=0.6,
                color_discrete_sequence=["#4ade80", "#FF69B4", "#facc15", "#f87171", "#54265E"]
            )
            fig_dist.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#FFFFFF" if st.session_state.theme == "dark" else "#2B1130",
                margin=dict(l=20, r=20, t=20, b=20)
            )
            st.plotly_chart(fig_dist, use_container_width=True)
        else:
            st.info("Belum ada data distribusi.")
        st.markdown('</div>', unsafe_allow_html=True)

    # Recent Scans Table
    st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
    st.subheader("📋 Pemindaian Terbaru")
    history_items = db.get_scan_history(limit=8)
    if history_items:
        df_hist = pd.DataFrame(history_items)[["timestamp", "domain", "status_code", "seo_score", "security_coverage", "response_time", "scan_id"]]
        df_hist.columns = ["Waktu", "Domain Target", "HTTP Status", "SEO Score", "Security %", "Latency (s)", "Scan ID"]
        st.dataframe(df_hist, )
    else:
        st.info("Riwayat pemindaian masih kosong. Jalankan scan pertama Anda!")
    st.markdown('</div>', unsafe_allow_html=True)


# ==========================================
# 2. WEBSITE SCANNER
# ==========================================
elif selected_menu == t["nav_scanner"]:
    render_header(t["nav_scanner"], "Multi-Vector Web & HTTP Header Security Analyzer")

    # Scanner Input Card
    st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
    sc1, sc2 = st.columns([3, 1])
    with sc1:
        target_input = st.text_input(
            "Target Website URL",
            placeholder=t["url_placeholder"],
            value=st.session_state.current_scan.get("url", "") if st.session_state.current_scan else "",
            help="Hanya protokol HTTP dan HTTPS yang didukung. Pembatasan SSRF aktif."
        )
    with sc2:
        st.write("") # spacing
        st.write("")
        scan_btn = st.button("🔍 Jalankan Scan Mendalam", use_container_width=True)

    # Preset Quick Targets
    st.markdown("<div style='font-size: 0.8rem; color: #C7A6BA; margin-top: 6px;'>Preset Contoh Target:</div>", unsafe_allow_html=True)
    p_cols = st.columns(4)
    preset_urls = ["https://google.com", "https://github.com", "https://wikipedia.org", "https://wordpress.org"]
    for i, p_url in enumerate(preset_urls):
        with p_cols[i]:
            if st.button(p_url.replace("https://", ""), key=f"p_{p_url}", use_container_width=True):
                run_full_scan(p_url)
                st.rerun()

    if scan_btn and target_input:
        run_full_scan(target_input)
        st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)

    # Display Scan Results
    curr = st.session_state.current_scan
    if curr:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("📊 Hasil Pemindaian Menyeluruh")

        # Top Details Grid
        r1, r2, r3, r4 = st.columns(4)
        with r1:
            st.metric("Domain", curr.get("domain"))
            st.metric("Server Header", curr.get("server") or "Undisclosed")
        with r2:
            st.metric("HTTP Status", f"{curr.get('status_code')} {curr.get('reason')}")
            st.metric("Powered By", curr.get("powered_by") or "Undisclosed")
        with r3:
            st.metric("Response Time", f"{curr.get('response_time')} detik")
            st.metric("Content-Type", curr.get("content_type", "")[:25])
        with r4:
            st.metric("Ukuran Respons", f"{round(curr.get('content_size', 0)/1024, 2)} KB")
            st.metric("Primary IP", curr.get("primary_ip") or "N/A")

        st.markdown("---")

        # Extended Metadata
        em1, em2 = st.columns(2)
        with em1:
            st.markdown(f"**URL Lengkap:** `{curr.get('url')}`")
            st.markdown(f"**URL Akhir (Setelah Redirect):** `{curr.get('final_url')}`")
            st.markdown(f"**Robots Meta Tag:** `{curr.get('seo', {}).get('meta', {}).get('robots', 'N/A')}`")
            st.markdown(f"**Canonical URL:** `{curr.get('seo', {}).get('meta', {}).get('canonical', 'N/A')}`")
        with em2:
            st.markdown(f"**Meta Author:** `{curr.get('seo', {}).get('meta', {}).get('author', 'N/A')}`")
            st.markdown(f"**Meta Keywords:** `{curr.get('seo', {}).get('meta', {}).get('keywords', 'N/A')}`")
            st.markdown(f"**Jumlah Cookies:** `{len(curr.get('cookies', []))}`")
            st.markdown(f"**Redirect Hops:** `{curr.get('redirect_count', 0)}`")

        # Redirect Chain Table if any
        if curr.get("redirect_chain"):
            st.markdown("##### 🔀 Rantai Pengalihan (Redirect Chain)")
            df_red = pd.DataFrame(curr.get("redirect_chain"))
            st.dataframe(df_red[["status_code", "url"]], use_container_width=True)

        # Raw Headers Expander
        with st.expander("📦 Lihat Semua HTTP Response Headers"):
            st.json(curr.get("headers", {}))

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("Silakan masukkan URL website di atas untuk memulai pemindaian.")


# ==========================================
# 3. TITLE DETECTOR
# ==========================================
elif selected_menu == t["nav_title"]:
    render_header(t["nav_title"], "HTML Title Tag Diagnostics & Google SERP Simulator")
    curr = st.session_state.current_scan

    if curr and curr.get("seo"):
        title_info = curr["seo"]["title"]
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("🏷️ Deteksi Judul Website (Title Tag)")

        t_col1, t_col2 = st.columns([3, 1])
        with t_col1:
            st.markdown(f"### `{title_info.get('text') or '[Title Tidak Ditemukan]'}`")
            status_cls = f"badge-{title_info.get('status')}"
            st.markdown(f"<span class='{status_cls}'>Status: {title_info.get('status').upper()}</span>", unsafe_allow_html=True)
            st.write("")
            st.info(f"💡 Rekomendasi: {title_info.get('recommendation')}")
        with t_col2:
            st.metric("Panjang Karakter", f"{title_info.get('length')} Karakter")
            st.caption("Ideal: 50 - 60 karakter")

        st.markdown("---")

        # Google SERP Simulator
        st.subheader("🔍 Simulasi Tampilan Google Search Results (SERP)")
        serp = title_info.get("serp_preview", {})
        st.markdown(f"""
            <div style="background: #ffffff; color: #202124; padding: 18px 24px; border-radius: 12px; border: 1px solid #dfe1e5; max-width: 650px; font-family: Roboto, Arial, sans-serif;">
                <div style="font-size: 0.8rem; color: #202124; display: flex; align-items: center; gap: 8px;">
                    <span style="background: #f1f3f4; border-radius: 50%; width: 22px; height: 22px; display: inline-flex; align-items: center; justify-content: center; font-size: 11px;">🌐</span>
                    <span>{serp.get('url')}</span>
                </div>
                <div style="color: #1a0dab; font-size: 1.25rem; font-weight: 400; line-height: 1.3; margin: 6px 0; text-decoration: underline; cursor: pointer;">
                    {serp.get('title')}
                </div>
                <div style="color: #4d5156; font-size: 0.88rem; line-height: 1.4;">
                    {serp.get('snippet')}
                </div>
            </div>
        """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(t["no_scan_desc"])


# ==========================================
# 4. META ANALYZER
# ==========================================
elif selected_menu == t["nav_meta"]:
    render_header(t["nav_meta"], "Meta Description, Robots, Viewport, Open Graph & Twitter Cards")
    curr = st.session_state.current_scan

    if curr and curr.get("seo"):
        meta = curr["seo"]["meta"]
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("📝 Metadata Dasar & SEO On-Page")

        desc = meta.get("description", {})
        st.markdown(f"**Meta Description:** `{desc.get('text') or '[Tidak Ada]'}`")
        st.caption(f"Panjang: {desc.get('length')} karakter. Rekomendasi: {desc.get('recommendation')}")

        st.markdown("---")
        m1, m2, m3 = st.columns(3)
        with m1:
            st.metric("Robots Meta", meta.get("robots") or "Default (index, follow)")
            st.metric("Author", meta.get("author") or "N/A")
        with m2:
            viewport = meta.get("viewport", {})
            st.metric("Mobile Viewport", "✅ Ditemukan" if viewport.get("present") else "❌ Hilang")
            st.caption(f"Content: `{viewport.get('content', 'N/A')}`")
        with m3:
            canonical = meta.get("canonical")
            st.metric("Rel Canonical", "✅ Terpasang" if canonical else "⚠️ Tidak Ada")
            st.caption(f"URL: `{canonical or 'N/A'}`")

        st.markdown("---")

        # Social Media Preview (Facebook Open Graph & Twitter Card)
        st.subheader("📱 Pratinjau Social Sharing (Open Graph & Twitter)")
        og = meta.get("open_graph", {})
        tw = meta.get("twitter_cards", {})

        s_col1, s_col2 = st.columns(2)
        with s_col1:
            st.markdown("##### Facebook / Open Graph Preview")
            og_img = og.get("og:image")
            st.markdown(f"""
                <div style="background: rgba(255,255,255,0.06); border: 1px solid rgba(255,79,163,0.3); border-radius: 12px; overflow: hidden; max-width: 450px;">
                    <div style="height: 180px; background: #26172B; display: flex; align-items: center; justify-content: center; color: #FF69B4;">
                        {'<img src="'+og_img+'" style="width:100%; height:100%; object-fit:cover;">' if og_img else '🖼️ Tidak Ada Gambar og:image'}
                    </div>
                    <div style="padding: 14px;">
                        <div style="font-size: 0.75rem; color: #C7A6BA; text-transform: uppercase;">{og.get('og:site_name', curr.get('domain'))}</div>
                        <div style="font-size: 0.95rem; font-weight: 700; color: #FFFFFF; margin: 4px 0;">{og.get('og:title', curr.get('seo', {}).get('title', {}).get('text', 'Judul'))}</div>
                        <div style="font-size: 0.8rem; color: #FFD6E8;">{og.get('og:description', desc.get('text', ''))[:100]}...</div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

        with s_col2:
            st.markdown("##### Twitter / X Card Preview")
            tw_img = tw.get("twitter:image") or og.get("og:image")
            st.markdown(f"""
                <div style="background: rgba(255,255,255,0.06); border: 1px solid rgba(255,79,163,0.3); border-radius: 16px; overflow: hidden; max-width: 450px;">
                    <div style="height: 180px; background: #110914; display: flex; align-items: center; justify-content: center; color: #FF69B4;">
                        {'<img src="'+tw_img+'" style="width:100%; height:100%; object-fit:cover;">' if tw_img else '🐦 Tidak Ada Gambar twitter:image'}
                    </div>
                    <div style="padding: 14px;">
                        <div style="font-size: 0.95rem; font-weight: 700; color: #FFFFFF;">{tw.get('twitter:title', og.get('og:title', 'Judul Twitter'))}</div>
                        <div style="font-size: 0.8rem; color: #FFD6E8; margin-top: 4px;">{tw.get('twitter:description', og.get('og:description', 'Deskripsi Twitter'))[:100]}...</div>
                        <div style="font-size: 0.75rem; color: #C7A6BA; margin-top: 6px;">🔗 {curr.get('domain')}</div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(t["no_scan_desc"])


# ==========================================
# 5. HEADING ANALYZER
# ==========================================
elif selected_menu == t["nav_headings"]:
    render_header(t["nav_headings"], "Heading Structure (H1 - H6) & Hierarchy Tree Validator")
    curr = st.session_state.current_scan

    if curr and curr.get("seo"):
        headings = curr["seo"]["headings"]
        counts = headings.get("counts", {})
        warnings = headings.get("warnings", [])

        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("📑 Ringkasan Jumlah Heading")

        hc_cols = st.columns(6)
        for i in range(1, 7):
            with hc_cols[i-1]:
                st.metric(f"Tag <H{i}>", counts.get(f"h{i}", 0))

        if warnings:
            st.markdown("---")
            st.markdown("##### ⚠️ Peringatan Struktur Heading")
            for w in warnings:
                st.warning(f"⚠️ {w}")

        st.markdown("---")
        st.subheader("🌳 Hierarki Pohon Heading")
        tree = headings.get("tree", [])
        if tree:
            for item in tree:
                indent = "&nbsp;" * ((item["level"] - 1) * 6)
                badge_color = "#FF4FA3" if item["level"] == 1 else ("#FF69B4" if item["level"] == 2 else "#C7A6BA")
                st.markdown(f"""
                    <div style="margin: 4px 0; font-family: 'JetBrains Mono', monospace; font-size: 0.88rem;">
                        {indent}<span style="background: rgba(255,79,163,0.15); color: {badge_color}; border: 1px solid {badge_color}; padding: 2px 6px; border-radius: 4px; font-weight: 700;">{item['tag']}</span>
                        <span style="color: #FFFFFF; margin-left: 8px;">{item['text']}</span>
                    </div>
                """, unsafe_allow_html=True)
        else:
            st.info("Tidak ada heading (H1 - H6) yang terdeteksi pada halaman ini.")

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(t["no_scan_desc"])


# ==========================================
# 6. LINK ANALYZER
# ==========================================
elif selected_menu == t["nav_links"]:
    render_header(t["nav_links"], "Internal vs External Link Audit, Anchor Text & Broken Link Detection")
    curr = st.session_state.current_scan

    if curr and curr.get("seo"):
        links = curr["seo"]["links"]
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("🔗 Statistik Tautan (Links)")

        l1, l2, l3, l4 = st.columns(4)
        with l1:
            st.metric("Total Link", links.get("total", 0))
        with l2:
            st.metric("Internal Links", links.get("internal_count", 0))
        with l3:
            st.metric("External Links", links.get("external_count", 0))
        with l4:
            st.metric("Link Tanpa Anchor", links.get("empty_anchors", 0))

        st.markdown("---")

        # Filter Tabs
        tab_int, tab_ext = st.tabs(["Internal Links (Sampel)", "External Links (Sampel)"])
        with tab_int:
            int_samples = links.get("internal_samples", [])
            if int_samples:
                df_int = pd.DataFrame(int_samples)
                st.dataframe(df_int, use_container_width=True)
            else:
                st.info("Tidak ada internal link terdeteksi.")

        with tab_ext:
            ext_samples = links.get("external_samples", [])
            if ext_samples:
                df_ext = pd.DataFrame(ext_samples)
                st.dataframe(df_ext, use_container_width=True)
            else:
                st.info("Tidak ada external link terdeteksi.")

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(t["no_scan_desc"])


# ==========================================
# 7. IMAGE ANALYZER
# ==========================================
elif selected_menu == t["nav_images"]:
    render_header(t["nav_images"], "Image Assets, Missing ALT Attributes, Format & Compression Audit")
    curr = st.session_state.current_scan

    if curr and curr.get("seo"):
        images = curr["seo"]["images"]
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("🖼️ Ringkasan Audit Gambar")

        i1, i2, i3, i4 = st.columns(4)
        with i1:
            st.metric("Total Gambar", images.get("total", 0))
        with i2:
            st.metric("ALT Coverage", f"{images.get('alt_coverage_pct', 0)}%")
        with i3:
            st.metric("Gambar Hilang ALT", images.get("missing_alt", 0))
        with i4:
            st.metric("Gambar Tanpa Sumber", images.get("missing_src", 0))

        st.markdown("---")

        # Format Distribution Chart
        fmt_dist = images.get("format_distribution", {})
        if fmt_dist:
            df_fmt = pd.DataFrame(list(fmt_dist.items()), columns=["Format", "Jumlah"])
            fig_fmt = px.pie(
                df_fmt, names="Format", values="Jumlah",
                hole=0.5,
                color_discrete_sequence=["#FF4FA3", "#FF69B4", "#FFD6E8", "#54265E", "#4ade80"]
            )
            fig_fmt.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#FFFFFF" if st.session_state.theme == "dark" else "#2B1130",
                margin=dict(l=20, r=20, t=20, b=20)
            )
            st.plotly_chart(fig_fmt, use_container_width=True)

        st.subheader("📋 Daftar Sampel Gambar")
        samples = images.get("samples", [])
        if samples:
            df_imgs = pd.DataFrame(samples)
            st.dataframe(df_imgs[["format", "has_alt", "alt", "src"]], use_container_width=True)
        else:
            st.info("Tidak ada gambar ditemukan pada halaman.")

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(t["no_scan_desc"])


# ==========================================
# 8. SEO AUDIT
# ==========================================
elif selected_menu == t["nav_seo"]:
    render_header(t["nav_seo"], "Comprehensive 0 - 100 SEO Scorecard & Quality Assessment")
    curr = st.session_state.current_scan

    if curr and curr.get("seo"):
        seo = curr["seo"]
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)

        # Gauge Chart for SEO Score
        g_col1, g_col2 = st.columns([1, 2])
        with g_col1:
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=seo.get("score", 0),
                title={"text": "SEO SCORE", "font": {"size": 20, "color": "#FF4FA3"}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#FF69B4"},
                    "bar": {"color": "#FF4FA3"},
                    "steps": [
                        {"range": [0, 50], "color": "rgba(239, 68, 68, 0.25)"},
                        {"range": [50, 75], "color": "rgba(234, 179, 8, 0.25)"},
                        {"range": [75, 100], "color": "rgba(34, 197, 94, 0.25)"}
                    ]
                }
            ))
            fig_gauge.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#FFFFFF" if st.session_state.theme == "dark" else "#2B1130",
                height=250,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

        with g_col2:
            st.markdown(f"## Grade Penilaian: <span style='color: #FF4FA3;'>{seo.get('grade')}</span>", unsafe_allow_html=True)
            st.markdown(f"*{seo.get('disclaimer')}*")
            st.write("")
            st.info("💡 **Tips Optimasi:** Fokuskan perbaikan pada checklist bertanda [FAIL] dan [WARN] di bawah ini.")

        st.markdown("---")

        # Detailed Transparent Checklist
        st.subheader("✅ Checklist Audit SEO Transparan")
        checklist = seo.get("checklist", [])
        for item in checklist:
            stat = item.get("status", "pass")
            stat_cls = f"badge-{stat}"
            st.markdown(f"""
                <div style="display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; margin-bottom: 8px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,79,163,0.2); border-radius: 8px;">
                    <div>
                        <strong style="color: #FFFFFF;">{item.get('item')}</strong>
                        <div style="font-size: 0.85rem; color: #C7A6BA;">{item.get('note')}</div>
                    </div>
                    <div style="text-align: right;">
                        <span class="{stat_cls}">{stat.upper()}</span>
                        <div style="font-size: 0.8rem; color: #FF69B4; font-weight: 600; margin-top: 2px;">{item.get('points')}</div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(t["no_scan_desc"])


# ==========================================
# 9. SECURITY ANALYZER
# ==========================================
elif selected_menu == t["nav_security"]:
    render_header(t["nav_security"], "Public Security Headers, TLS Certificate & Cookie Audit")
    curr = st.session_state.current_scan

    if curr and curr.get("security"):
        sec = curr["security"]
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)

        # Overview Metrics
        s1, s2, s3, s4 = st.columns(4)
        with s1:
            st.metric("Security Grade", sec.get("grade", "N/A"))
        with s2:
            st.metric("Header Coverage", f"{sec.get('coverage_pct', 0)}%")
        with s3:
            st.metric("Header Terpasang", f"{sec.get('present_headers_count', 0)} / {sec.get('total_headers_checked', 6)}")
        with s4:
            ssl_stat = sec.get("ssl_certificate", {}).get("status_label", "N/A")
            st.metric("Status SSL", ssl_stat)

        st.caption(f"🛡️ *{sec.get('disclaimer')}*")
        st.markdown("---")

        # SSL/TLS Certificate Details
        st.subheader("🔐 Informasi Sertifikat SSL/TLS")
        ssl_info = sec.get("ssl_certificate", {})
        if ssl_info.get("status") in ("valid", "expired"):
            sc1, sc2, sc3 = st.columns(3)
            with sc1:
                st.markdown(f"**Common Name:** `{ssl_info.get('common_name')}`")
                st.markdown(f"**Issuer:** `{ssl_info.get('issuer_name')}`")
            with sc2:
                st.markdown(f"**Mulai Berlaku:** `{ssl_info.get('valid_from')}`")
                st.markdown(f"**Berakhir Pada:** `{ssl_info.get('valid_to')}`")
            with sc3:
                st.markdown(f"**Sisa Masa Aktif:** `{ssl_info.get('days_remaining')} hari`")
                st.markdown(f"**Protokol TLS:** `{ssl_info.get('tls_version')} ({ssl_info.get('cipher_suite')})`")
        else:
            st.warning(f"Sertifikat SSL: {ssl_info.get('error') or 'Tidak menggunakan HTTPS'}")

        st.markdown("---")

        # Security Headers Table
        st.subheader("🛡️ Hasil Evaluasi Header Keamanan Publik")
        headers_list = sec.get("headers", [])
        for h in headers_list:
            present = h.get("present")
            badge = "<span class='badge-pass'>PASS</span>" if present else "<span class='badge-fail'>MISSING</span>"
            val_txt = f"<code style='color: #4ade80;'>{h.get('value')}</code>" if present else f"<span style='color: #f87171;'>Header belum dikonfigurasikan</span>"
            st.markdown(f"""
                <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,79,163,0.25); border-radius: 10px; padding: 12px 16px; margin-bottom: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong style="color: #FF69B4; font-size: 1rem;">{h.get('name')}</strong>
                        {badge}
                    </div>
                    <div style="font-size: 0.85rem; color: #C7A6BA; margin: 4px 0;">{h.get('description')}</div>
                    <div style="margin-top: 6px; font-size: 0.85rem;">{val_txt}</div>
                    {f"<div style='margin-top: 6px; font-size: 0.8rem; color: #facc15;'>💡 Saran: {h.get('advice')}</div>" if not present else ""}
                </div>
            """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(t["no_scan_desc"])


# ==========================================
# 10. IP & DNS ANALYZER
# ==========================================
elif selected_menu == t["nav_network"]:
    render_header(t["nav_network"], "Public DNS Records (A, AAAA, MX, NS, CNAME, TXT) & IP Geolocation")
    curr = st.session_state.current_scan

    if curr and curr.get("network"):
        net = curr["network"]
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("🌐 Resolusi Alamat IP & DNS Publik")

        st.markdown(f"**Hostname Target:** `{net.get('hostname')}` | **Waktu Resolusi:** `{net.get('timestamp')}`")
        st.caption(f"Sumber Data: {net.get('source')}")
        st.markdown("---")

        # Geolocation Cards
        geo = net.get("geolocation", {})
        g1, g2, g3, g4 = st.columns(4)
        with g1:
            st.metric("Negara", geo.get("country", "N/A"))
        with g2:
            st.metric("Kota / Wilayah", f"{geo.get('city', '')}, {geo.get('region', '')}")
        with g3:
            st.metric("ISP Penyedia", geo.get("isp", "N/A"))
        with g4:
            st.metric("Autonomous System (ASN)", geo.get("asn", "N/A")[:20])

        st.markdown("---")

        # DNS Records
        st.subheader("📡 DNS Record Publik")
        d1, d2 = st.columns(2)
        with d1:
            st.markdown("##### Record A (IPv4)")
            a_recs = net.get("all_a_records", [])
            for a in a_recs:
                st.code(a, language="bash")

            st.markdown("##### Record AAAA (IPv6)")
            aaaa_recs = net.get("all_aaaa_records", [])
            if aaaa_recs:
                for aaaa in aaaa_recs:
                    st.code(aaaa, language="bash")
            else:
                st.info("Record AAAA tidak ditemukan.")

            st.markdown("##### Reverse DNS (PTR Record)")
            st.code(net.get("ptr_record", "N/A"), language="bash")

        with d2:
            st.markdown("##### Record MX (Mail Exchange)")
            mx_recs = net.get("mx_records", [])
            if mx_recs:
                for mx in mx_recs:
                    st.code(mx, language="bash")
            else:
                st.info("Record MX tidak ditemukan.")

            st.markdown("##### Record NS (Name Servers)")
            ns_recs = net.get("ns_records", [])
            if ns_recs:
                for ns in ns_recs:
                    st.code(ns, language="bash")
            else:
                st.info("Record NS tidak ditemukan.")

            st.markdown("##### Record TXT")
            txt_recs = net.get("txt_records", [])
            if txt_recs:
                for txt in txt_recs[:5]:
                    st.code(txt, language="bash")
            else:
                st.info("Record TXT tidak ditemukan.")

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(t["no_scan_desc"])


# ==========================================
# 11. TECHNOLOGY DETECTOR
# ==========================================
elif selected_menu == t["nav_tech"]:
    render_header(t["nav_tech"], "Heuristic Technology Stack & CMS Fingerprinting")
    curr = st.session_state.current_scan

    if curr:
        techs = curr.get("tech_stack", [])
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("🔍 Teknologi Terdeteksi pada Website Target")
        st.caption("Deteksi berdasarkan signature heuristik publik (HTML meta tags, asset bundle, script signatures, dan server headers).")

        if techs:
            t_cols = st.columns(3)
            for idx, tech in enumerate(techs):
                with t_cols[idx % 3]:
                    st.markdown(f"""
                        <div style="background: rgba(255,79,163,0.1); border: 1px solid rgba(255,79,163,0.4); border-radius: 12px; padding: 14px; margin-bottom: 12px;">
                            <div style="font-size: 0.75rem; color: #FF69B4; font-weight: 600; text-transform: uppercase;">{tech.get('category')}</div>
                            <div style="font-size: 1.15rem; font-weight: 800; color: #FFFFFF; margin: 2px 0;">{tech.get('name')}</div>
                            <div style="font-size: 0.8rem; color: #4ade80; font-weight: 600;">Keyakinan: {tech.get('confidence')}</div>
                            <div style="font-size: 0.78rem; color: #C7A6BA; margin-top: 6px;">Bukti: {tech.get('evidence')}</div>
                        </div>
                    """, unsafe_allow_html=True)
        else:
            st.info("Tidak ada signature teknologi khusus yang cocok dengan database heuristik publik.")

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(t["no_scan_desc"])


# ==========================================
# 12. PERFORMANCE ANALYZER
# ==========================================
elif selected_menu == t["nav_perf"]:
    render_header(t["nav_perf"], "HTTP Transfer Latency, Caching, Compression & Optimization Roadmap")
    curr = st.session_state.current_scan

    if curr and curr.get("performance"):
        perf = curr["performance"]
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("⚡ Ringkasan Kinerja Jaringan HTTP")

        p1, p2, p3, p4 = st.columns(4)
        with p1:
            st.metric("Response Time", f"{perf.get('response_time_sec', 0)} detik")
        with p2:
            st.metric("Ukuran Dokumen", f"{perf.get('content_size_kb', 0)} KB")
        with p3:
            comp_status = "✅ Aktif" if perf.get("compression", {}).get("enabled") else "❌ Tidak Aktif"
            st.metric("Kompresi HTTP", comp_status)
        with p4:
            st.metric("Rating Performa", perf.get("rating", "N/A"))

        st.caption(f"⚡ *{perf.get('disclaimer')}*")
        st.markdown("---")

        # Caching Details
        st.subheader("🗄️ Konfigurasi Caching Browser")
        caching = perf.get("caching", {})
        c_col1, c_col2 = st.columns(2)
        with c_col1:
            st.markdown(f"**Cache-Control:** `{caching.get('cache_control')}`")
            st.markdown(f"**ETag:** `{caching.get('etag')}`")
        with c_col2:
            st.markdown(f"**Expires:** `{caching.get('expires')}`")
            st.markdown(f"**Age:** `{caching.get('age')}`")

        st.markdown("---")

        # Performance Recommendations
        st.subheader("💡 Rekomendasi Optimasi Kinerja")
        recs = perf.get("recommendations", [])
        if recs:
            for r in recs:
                st.warning(f"⚡ {r}")
        else:
            st.success("Performa jaringan website ini telah teroptimasi dengan sangat baik!")

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(t["no_scan_desc"])


# ==========================================
# 13. ROBOTS & SITEMAP
# ==========================================
elif selected_menu == t["nav_robots"]:
    render_header(t["nav_robots"], "Robots.txt Directives & Sitemap.xml URL Discovery")
    curr = st.session_state.current_scan

    if curr:
        robots = curr.get("robots", {})
        sitemap = curr.get("sitemap", {})

        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("🤖 Analisis Robots.txt")
        st.markdown(f"**URL:** `{robots.get('url')}` | **Status:** `{robots.get('status_code')}`")
        st.markdown(f"**Sitemap Terdeteksi di Robots.txt:** `{len(robots.get('sitemaps', []))} sitemap`")

        if robots.get("exists"):
            with st.expander("📄 Lihat Konten Mentah robots.txt", expanded=True):
                st.code(robots.get("content", ""), language="text")
        else:
            st.warning("File robots.txt tidak ditemukan atau tidak dapat diakses (HTTP Status != 200).")

        st.markdown("---")

        st.subheader("🗺️ Analisis Sitemap.xml")
        st.markdown(f"**URL:** `{sitemap.get('url')}` | **Status:** `{sitemap.get('status_code')}`")
        st.metric("Total URL Terdeteksi di Sitemap", sitemap.get("url_count", 0))

        if sitemap.get("sample_urls"):
            st.markdown("##### Sampel URL dari Sitemap:")
            df_sm = pd.DataFrame(sitemap.get("sample_urls", []), columns=["Sample URLs"])
            st.dataframe(df_sm, use_container_width=True)

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(t["no_scan_desc"])


# ==========================================
# 14. SCAN HISTORY
# ==========================================
elif selected_menu == t["nav_history"]:
    render_header(t["nav_history"], "Database Scan History Management & Search")

    # Search & Filter Controls
    h_col1, h_col2, h_col3 = st.columns([3, 2, 1])
    with h_col1:
        search_kw = st.text_input("Cari Riwayat Berdasarkan Domain / URL", placeholder="contoh: google.com")
    with h_col2:
        date_pick = st.date_input("Filter Tanggal (Opsional)", value=None)
    with h_col3:
        st.write("")
        st.write("")
        date_str = date_pick.strftime("%Y-%m-%d") if date_pick else None

    # Load history from SQLite
    history = db.get_scan_history(limit=50, search_query=search_kw, date_filter=date_str)

    st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
    st.subheader(f"📜 Riwayat Pemindaian ({len(history)} entri ditemukan)")

    if history:
        for item in history:
            hc1, hc2, hc3, hc4 = st.columns([3, 2, 2, 2])
            with hc1:
                fav_icon = "⭐" if item.get("is_favorite") else "☆"
                st.markdown(f"**{fav_icon} {item.get('domain')}**")
                st.caption(f"{item.get('timestamp')} | ID: `{item.get('scan_id')}`")
            with hc2:
                st.markdown(f"Status: `{item.get('status_code')}`")
                st.markdown(f"SEO: `{item.get('seo_score')}/100`")
            with hc3:
                st.markdown(f"Security: `{item.get('security_coverage')}%`")
                st.markdown(f"Latency: `{item.get('response_time')}s`")
            with hc4:
                b_col1, b_col2 = st.columns(2)
                with b_col1:
                    if st.button("👁️ Buka", key=f"open_{item.get('scan_id')}"):
                        full_obj = db.get_scan_by_id(item.get("scan_id"))
                        if full_obj:
                            st.session_state.current_scan = full_obj
                            st.success(f"Target '{item.get('domain')}' berhasil dimuat!")
                            time.sleep(0.5)
                            st.rerun()
                with b_col2:
                    if st.button("🗑️ Hapus", key=f"del_{item.get('scan_id')}"):
                        db.delete_scan(item.get("scan_id"))
                        st.rerun()
            st.markdown("<hr style='margin: 8px 0;'>", unsafe_allow_html=True)

        st.markdown("---")
        # Clear All Scans Button with Safety Confirmation
        with st.expander("⚠️ Tindakan Berbahaya: Hapus Seluruh Riwayat"):
            confirm_clear = st.checkbox("Saya yakin ingin menghapus SELURUH riwayat pemindaian.")
            if confirm_clear and st.button("🚨 Bersihkan Semua Riwayat Database"):
                db.clear_all_scans()
                st.session_state.current_scan = None
                st.success("Seluruh riwayat database berhasil dibersihkan.")
                st.rerun()
    else:
        st.info("Tidak ada riwayat pemindaian yang cocok dengan filter.")

    st.markdown('</div>', unsafe_allow_html=True)


# ==========================================
# 15. REPORT CENTER
# ==========================================
elif selected_menu == t["nav_report"]:
    render_header(t["nav_report"], "Export Professional PDF, CSV & JSON Cyber Audit Reports")
    curr = st.session_state.current_scan

    if curr:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("📑 Pusat Pengunduhan Laporan (Export Center)")
        st.markdown(f"Laporan audit untuk target: **{curr.get('domain')}** (`{curr.get('url')}`)")

        rep_c1, rep_c2, rep_c3 = st.columns(3)

        # 1. PDF Export
        with rep_c1:
            st.markdown("##### 📄 Laporan PDF Profesional")
            st.caption("Laporan lengkap bergaya Pink Cyber Security siap cetak.")
            pdf_bytes = report_generator.generate_pdf_report(curr)
            st.download_button(
                label="📥 Unduh PDF Report",
                data=pdf_bytes,
                file_name=f"PinkWebScanner_Audit_{curr.get('domain')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )

        # 2. CSV Export
        with rep_c2:
            st.markdown("##### 📊 Ringkasan Format CSV")
            st.caption("Data tabulasi metrik SEO, Security, dan Teknologi.")
            csv_str = report_generator.generate_csv_report(curr)
            st.download_button(
                label="📥 Unduh CSV Report",
                data=csv_str,
                file_name=f"PinkWebScanner_{curr.get('domain')}.csv",
                mime="text/csv",
                use_container_width=True
            )

        # 3. JSON Export
        with rep_c3:
            st.markdown("##### 📦 Full Dataset JSON")
            st.caption("Data mentah lengkap hasil pemindaian dan audit.")
            json_str = report_generator.generate_json_report(curr)
            st.download_button(
                label="📥 Unduh JSON Dataset",
                data=json_str,
                file_name=f"PinkWebScanner_{curr.get('domain')}.json",
                mime="application/json",
                use_container_width=True
            )

        st.markdown("---")

        # In-App Printable Report Preview
        st.subheader("🖨️ Pratinjau Laporan Siap Cetak (Print View)")
        st.markdown(f"""
            <div style="background: rgba(255,255,255,0.04); border: 2px dashed rgba(255,79,163,0.5); border-radius: 14px; padding: 24px; font-family: 'Inter', sans-serif;">
                <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #FF4FA3; padding-bottom: 12px; margin-bottom: 16px;">
                    <div>
                        <h2 style="color: #FF4FA3; margin: 0;">🛡️ PINK WEB SCANNER</h2>
                        <span style="font-size: 0.75rem; color: #FF69B4; letter-spacing: 1.5px;">CYBER SECURITY & SEO AUDIT REPORT</span>
                    </div>
                    <div style="text-align: right; font-size: 0.85rem; color: #C7A6BA;">
                        Tanggal: {curr.get('timestamp')}<br>Scan ID: {curr.get('scan_id')}
                    </div>
                </div>

                <div style="margin-bottom: 16px;">
                    <strong>Target Website:</strong> <a href="{curr.get('url')}" style="color: #FF69B4;">{curr.get('url')}</a><br>
                    <strong>IP Address:</strong> {curr.get('primary_ip')} | <strong>HTTP Status:</strong> {curr.get('status_code')} {curr.get('reason')}
                </div>

                <div style="display: flex; gap: 16px; margin-bottom: 20px;">
                    <div style="flex: 1; background: rgba(84,38,94,0.4); border: 1px solid #FF4FA3; border-radius: 8px; padding: 12px; text-align: center;">
                        <div style="font-size: 0.75rem; color: #C7A6BA;">SEO SCORE</div>
                        <div style="font-size: 1.6rem; font-weight: 800; color: #FF4FA3;">{curr.get('seo_score')}/100</div>
                    </div>
                    <div style="flex: 1; background: rgba(84,38,94,0.4); border: 1px solid #FF4FA3; border-radius: 8px; padding: 12px; text-align: center;">
                        <div style="font-size: 0.75rem; color: #C7A6BA;">SECURITY COVERAGE</div>
                        <div style="font-size: 1.6rem; font-weight: 800; color: #FF4FA3;">{curr.get('security_coverage')}%</div>
                    </div>
                    <div style="flex: 1; background: rgba(84,38,94,0.4); border: 1px solid #FF4FA3; border-radius: 8px; padding: 12px; text-align: center;">
                        <div style="font-size: 0.75rem; color: #C7A6BA;">RESPONSE TIME</div>
                        <div style="font-size: 1.6rem; font-weight: 800; color: #FF4FA3;">{curr.get('response_time')}s</div>
                    </div>
                </div>

                <div style="font-size: 0.85rem; color: #FFD6E8;">
                    <strong>Rekomendasi Utama:</strong><br>
                    {'<br>'.join(['• ' + r for r in (curr.get('security', {}).get('recommendations', []) + curr.get('performance', {}).get('recommendations', []))[:5]])}
                </div>
            </div>
        """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning(t["no_scan_desc"])


# ==========================================
# 16. COMPARISON TOOL
# ==========================================
elif selected_menu == t["nav_compare"]:
    render_header(t["nav_compare"], "Side-by-Side Website Benchmark & Differential Audit")

    st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
    st.subheader("⚖️ Komparasi Dua Website")

    comp_c1, comp_c2 = st.columns(2)
    with comp_c1:
        url_a = st.text_input("URL Website A", value="https://google.com")
    with comp_c2:
        url_b = st.text_input("URL Website B", value="https://wikipedia.org")

    if st.button("🔥 Bandingkan Sekarang", use_container_width=True):
        with st.spinner("Memindai Website A dan Website B secara bersamaan..."):
            res_a = scanner.scan_website(url_a)
            res_b = scanner.scan_website(url_b)

            if res_a.get("success") and res_b.get("success"):
                seo_a = seo_analyzer.analyze_seo(res_a.get("html", ""), res_a.get("final_url", url_a))
                seo_b = seo_analyzer.analyze_seo(res_b.get("html", ""), res_b.get("final_url", url_b))

                sec_a = security_analyzer.analyze_security(res_a.get("headers", {}), res_a.get("final_url", url_a))
                sec_b = security_analyzer.analyze_security(res_b.get("headers", {}), res_b.get("final_url", url_b))

                tech_a = tech_detector.detect_technologies(res_a.get("html", ""), res_a.get("headers", {}))
                tech_b = tech_detector.detect_technologies(res_b.get("html", ""), res_b.get("headers", {}))

                st.markdown("---")
                st.subheader("📊 Tabel Perbandingan Langsung")

                comp_data = [
                    {"Parameter": "Domain", "Website A": res_a.get("domain"), "Website B": res_b.get("domain")},
                    {"Parameter": "HTTP Status", "Website A": f"{res_a.get('status_code')} {res_a.get('reason')}", "Website B": f"{res_b.get('status_code')} {res_b.get('reason')}"},
                    {"Parameter": "Title Website", "Website A": seo_a.get("title", {}).get("text")[:40] + "...", "Website B": seo_b.get("title", {}).get("text")[:40] + "..."},
                    {"Parameter": "SEO Score (0-100)", "Website A": f"{seo_a.get('score')} ({seo_a.get('grade')})", "Website B": f"{seo_b.get('score')} ({seo_b.get('grade')})"},
                    {"Parameter": "Security Coverage (%)", "Website A": f"{sec_a.get('coverage_pct')}%", "Website B": f"{sec_b.get('coverage_pct')}%"},
                    {"Parameter": "Response Time (s)", "Website A": f"{res_a.get('response_time')}s", "Website B": f"{res_b.get('response_time')}s"},
                    {"Parameter": "Jumlah Link", "Website A": seo_a.get("links", {}).get("total", 0), "Website B": seo_b.get("links", {}).get("total", 0)},
                    {"Parameter": "Jumlah Gambar", "Website A": seo_a.get("images", {}).get("total", 0), "Website B": seo_b.get("images", {}).get("total", 0)},
                    {"Parameter": "Teknologi Terdeteksi", "Website A": f"{len(tech_a)} teknologi", "Website B": f"{len(tech_b)} teknologi"}
                ]

                st.dataframe(pd.DataFrame(comp_data), use_container_width=True)

                # Radar Comparison Chart
                categories = ["SEO Score", "Security Coverage", "Link Density", "Image Density"]
                val_a = [
                    seo_a.get("score", 0),
                    sec_a.get("coverage_pct", 0),
                    min(100, seo_a.get("links", {}).get("total", 0)),
                    min(100, seo_a.get("images", {}).get("total", 0))
                ]
                val_b = [
                    seo_b.get("score", 0),
                    sec_b.get("coverage_pct", 0),
                    min(100, seo_b.get("links", {}).get("total", 0)),
                    min(100, seo_b.get("images", {}).get("total", 0))
                ]

                fig_radar = go.Figure()
                fig_radar.add_trace(go.Scatterpolar(r=val_a, theta=categories, fill='toself', name=res_a.get("domain"), line_color="#FF4FA3"))
                fig_radar.add_trace(go.Scatterpolar(r=val_b, theta=categories, fill='toself', name=res_b.get("domain"), line_color="#4ade80"))
                fig_radar.update_layout(
                    polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
                    paper_bgcolor="rgba(0,0,0,0)",
                    font_color="#FFFFFF" if st.session_state.theme == "dark" else "#2B1130"
                )
                st.plotly_chart(fig_radar, use_container_width=True)
            else:
                st.error("Gagal memindai salah satu atau kedua target. Periksa kembali URL Anda.")

    st.markdown('</div>', unsafe_allow_html=True)


# ==========================================
# 17. LEARNING CENTER
# ==========================================
elif selected_menu == t["nav_learn"]:
    render_header(t["nav_learn"], "Interactive Web Fundamentals & Cyber Security Academy")

    st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
    st.subheader("📚 Ensiklopedia Jaringan & Keamanan Web")

    learn_tabs = st.tabs([
        "🌐 Web & HTML",
        "🔒 HTTP & HTTPS",
        "📡 DNS & IP",
        "🔐 SSL/TLS",
        "📈 SEO Dasar",
        "🛡️ Security Headers",
        "🎯 Kuis Interaktif"
    ])

    with learn_tabs[0]:
        st.markdown("""
            ### 🌐 Pengertian Website & HTML
            - **Website:** Kumpulan halaman web yang saling terhubung di bawah satu nama domain dan di-hosting pada server web publik.
            - **HTML (HyperText Markup Language):** Bahasa markup standar untuk menstrukturkan halaman web menggunakan elemen dan tag (seperti `<title>`, `<meta>`, `<h1>`, `<p>`, `<a>`, `<img>`).
            - **DOM (Document Object Model):** Representasi pohon hierarkis objek dari dokumen HTML yang diproses oleh browser web.
        """)

    with learn_tabs[1]:
        st.markdown("""
            ### 🔒 Protokol HTTP vs HTTPS
            - **HTTP (Hypertext Transfer Protocol):** Protokol komunikasi tanpa enkripsi pada port 80. Data dikirim dalam format plain text, rentan terhadap penyadapan (Man-In-The-Middle / MITM).
            - **HTTPS (HTTP Secure):** Protokol HTTP yang dilapisi enkripsi TLS/SSL pada port 443. Menjamin kerahasiaan (*confidentiality*), integritas (*integrity*), dan autentikasi (*authentication*).
        """)

    with learn_tabs[2]:
        st.markdown("""
            ### 📡 DNS & IP Address
            - **IP Address:** Alamat unik numerik perangkat di jaringan (IPv4: format 32-bit seperti `93.184.216.34`; IPv6: format 128-bit).
            - **DNS (Domain Name System):** Buku telepon internet yang menerjemahkan nama domain yang mudah diingat (`google.com`) menjadi IP address server.
            - **Record Utama:** `A` (IPv4), `AAAA` (IPv6), `MX` (Server Email), `NS` (Name Server), `CNAME` (Alias), `TXT` (Verifikasi & SPF).
        """)

    with learn_tabs[3]:
        st.markdown("""
            ### 🔐 SSL / TLS Certificate
            - **TLS (Transport Layer Security):** Protokol kriptografi modern pengganti SSL untuk mengenkripsi saluran komunikasi internet.
            - **Sertifikat Digital:** File elektronik yang diterbitkan oleh Certificate Authority (CA) terpercaya untuk memvalidasi identitas pemilik website dan kunci publik.
        """)

    with learn_tabs[4]:
        st.markdown("""
            ### 📈 SEO (Search Engine Optimization)
            - **Title Tag:** Elemen terpenting penentu judul halaman di SERP (Rekomendasi: 50-60 karakter).
            - **Meta Description:** Ringkasan konten halaman untuk memikat pengguna mengklik link (Rekomendasi: 120-160 karakter).
            - **Heading Hierarchy:** Struktur H1 (topik utama), H2 (sub-topik), H3 (turunan sub-topik) untuk memudahkan web crawler memahami konteks.
            - **Alt Text:** Teks alternatif gambar untuk aksesibilitas pembaca layar dan SEO gambar.
        """)

    with learn_tabs[5]:
        st.markdown("""
            ### 🛡️ HTTP Security Headers
            - **HSTS (Strict-Transport-Security):** Mencegah penurunan protokol (downgrade attack) ke HTTP biasa.
            - **CSP (Content-Security-Policy):** Mencegah serangan Cross-Site Scripting (XSS) dan pemuatan skrip berbahaya.
            - **X-Frame-Options:** Melindungi situs dari Clickjacking dengan mengatur apakah situs boleh dimasukkan dalam `<iframe>`.
            - **X-Content-Type-Options:** Mencegah MIME-sniffing browser.
        """)

    with learn_tabs[6]:
        st.markdown("### 🎯 Kuis Singkat Cyber Security & Web")
        st.write("Uji pemahaman Anda mengenai dasar-dasar web dan keamanan internet.")

        q1 = st.radio("1. Apa fungsi utama dari header Strict-Transport-Security (HSTS)?", [
            "Mempercepat waktu unduh gambar",
            "Memaksa browser hanya membuka website via HTTPS terenkripsi",
            "Menghapus cache browser otomatis",
            "Memblokir semua iklan di website"
        ])

        q2 = st.radio("2. Berapa rentang panjang karakter yang ideal untuk tag <title> menurut standar SEO?", [
            "10 - 20 karakter",
            "50 - 60 karakter",
            "150 - 200 karakter",
            "Bebas tanpa batasan"
        ])

        q3 = st.radio("3. Apa tujuan dari serangan SSRF (Server-Side Request Forgery) yang dicegah oleh scanner ini?", [
            "Memaksa server memindai atau mengakses jaringan privat/internal internal korban",
            "Menghapus database browser pengguna",
            "Mengubah font tampilan website",
            "Mematikan router WiFi pengguna"
        ])

        if st.button("📝 Periksa Jawaban Kuis"):
            score = 0
            if q1 == "Memaksa browser hanya membuka website via HTTPS terenkripsi":
                score += 1
            if q2 == "50 - 60 karakter":
                score += 1
            if q3 == "Memaksa server memindai atau mengakses jaringan privat/internal internal korban":
                score += 1

            if score == 3:
                st.balloons()
                st.success(f"🎉 Sempurna! Skor Anda: 3/3 (100%). Anda memahami konsep web security dengan sangat baik!")
            else:
                st.warning(f"Skor Anda: {score}/3. Pelajari kembali materi pada tab ensiklopedia di atas.")

    st.markdown('</div>', unsafe_allow_html=True)


# ==========================================
# 18. SETTINGS
# ==========================================
elif selected_menu == t["nav_settings"]:
    render_header(t["nav_settings"], "Scanner Configuration, Themes, Database Management & Developer Info")

    st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
    st.subheader("⚙️ Pengaturan Scanner & Sistem")

    # Scanner Network Config
    cfg_col1, cfg_col2 = st.columns(2)
    with cfg_col1:
        new_timeout = st.slider("Request Timeout (Detik)", min_value=3, max_value=30, value=st.session_state.timeout)
        if new_timeout != st.session_state.timeout:
            st.session_state.timeout = new_timeout
            db.save_setting("timeout", str(new_timeout))
            st.toast("Timeout diperbarui!", icon="⚙️")

        ua_options = [
            "PinkWebScanner Default (CyberSecurityAuditor)",
            "Chrome 122 Windows Desktop",
            "Googlebot 2.1 (SEO Simulator)"
        ]
        ua_choice = st.selectbox("Pilihan User-Agent", ua_options, index=0)

    with cfg_col2:
        new_verify_ssl = st.checkbox("Verifikasi Sertifikat SSL/TLS saat Request", value=st.session_state.verify_ssl)
        if new_verify_ssl != st.session_state.verify_ssl:
            st.session_state.verify_ssl = new_verify_ssl
            db.save_setting("verify_ssl", str(new_verify_ssl))
            st.toast("Pengaturan Verifikasi SSL diperbarui!", icon="⚙️")

        st.info("💡 **SSRF Shield:** Proteksi SSRF (Server-Side Request Forgery) selalu aktif dan secara permanen memblokir loopback, localhost, serta IP privat (RFC 1918).")

    st.markdown("---")

    # About Developer & Architecture
    st.subheader("🛡️ Tentang Pink Web Scanner")
    st.markdown("""
        **PINK WEB SCANNER** adalah platform Web Security & SEO Intelligence canggih yang dirancang dengan estetika *Futuristic Cyber Security*.
        
        - **Versi:** 1.0.0 Pro Suite
        - **Engine:** Python 3.11+, Streamlit, BeautifulSoup, Requests, Plotly, SQLite
        - **Desain & Palet:** Hot Pink (`#FF4FA3`), Neon Pink (`#FF69B4`), Deep Purple (`#54265E`), Glassmorphism Dark/Light Mode.
        - **Keamanan:** Dilengkapi SSRF Defense, Host Filtering, Stream Size Limiter, passive TLS/SSL inspector.
        - **Lisensi:** MIT Open-Source Cybersecurity License.
        
        *DISCOVER • ANALYZE • PROTECT • UNDERSTAND*
    """)

    st.markdown('</div>', unsafe_allow_html=True)
