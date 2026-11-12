"""
PINK WEB SCANNER - REPORT GENERATOR
Generates professional cybersecurity audit reports in PDF, CSV, and JSON formats,
complete with executive summaries, metrics, and actionable hardening roadmaps.
"""

import json
import io
import pandas as pd
from datetime import datetime
from typing import Dict, Any

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

def generate_json_report(scan_data: Dict[str, Any]) -> str:
    """Returns formatted JSON string of the complete scan dataset."""
    return json.dumps(scan_data, indent=2, ensure_ascii=False)

def generate_csv_report(scan_data: Dict[str, Any]) -> str:
    """Returns CSV string summarizing core audit metrics and checklist."""
    rows = [
        {"Category": "General", "Metric": "Target URL", "Value": scan_data.get("url", "")},
        {"Category": "General", "Metric": "Primary Domain", "Value": scan_data.get("domain", "")},
        {"Category": "General", "Metric": "IP Address", "Value": scan_data.get("primary_ip", "")},
        {"Category": "General", "Metric": "HTTP Status", "Value": scan_data.get("status_code", 0)},
        {"Category": "General", "Metric": "Scan Date", "Value": scan_data.get("timestamp", "")},
        {"Category": "SEO", "Metric": "SEO Score", "Value": f"{scan_data.get('seo_score', 0)}/100 ({scan_data.get('seo_grade', 'N/A')})"},
        {"Category": "SEO", "Metric": "Page Title", "Value": scan_data.get("seo", {}).get("title", {}).get("text", "")},
        {"Category": "SEO", "Metric": "Total Links", "Value": scan_data.get("seo", {}).get("links", {}).get("total", 0)},
        {"Category": "SEO", "Metric": "Total Images", "Value": scan_data.get("seo", {}).get("images", {}).get("total", 0)},
        {"Category": "Security", "Metric": "Security Coverage", "Value": f"{scan_data.get('security_coverage', 0)}%"},
        {"Category": "Security", "Metric": "Security Grade", "Value": scan_data.get("security", {}).get("grade", "N/A")},
        {"Category": "Performance", "Metric": "Response Time", "Value": f"{scan_data.get('response_time', 0)}s"},
        {"Category": "Performance", "Metric": "Performance Rating", "Value": scan_data.get("performance", {}).get("rating", "N/A")},
        {"Category": "Performance", "Metric": "HTML Size", "Value": f"{scan_data.get('performance', {}).get('content_size_kb', 0)} KB"},
    ]

    # Append detected tech
    for tech in scan_data.get("tech_stack", []):
        rows.append({"Category": "Technology", "Metric": tech.get("category", "Tech"), "Value": f"{tech.get('name')} ({tech.get('confidence')})"})

    df = pd.DataFrame(rows)
    return df.to_csv(index=False)

class PinkCyberPDF(FPDF if HAS_FPDF else object):
    """Custom FPDF class styled with Pink Web Scanner aesthetics."""
    def header(self):
        # Header banner
        self.set_fill_color(84, 38, 94)  # Deep Purple
        self.rect(0, 0, 210, 24, "F")
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(255, 105, 180)  # Neon Pink
        self.cell(0, 10, "PINK WEB SCANNER - AUDIT REPORT", 0, 1, "L")
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(255, 214, 232)
        self.cell(0, 4, "DISCOVER . ANALYZE . PROTECT . UNDERSTAND", 0, 1, "L")
        self.ln(12)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(160, 120, 150)
        self.cell(0, 10, f"Page {self.page_no()} | Pink Web Scanner Professional Cyber Suite", 0, 0, "C")

def generate_pdf_report(scan_data: Dict[str, Any]) -> bytes:
    """Generates a styled PDF report in bytes."""
    if not HAS_FPDF:
        return b"%PDF-1.4 Fallback: fpdf2 not installed."

    pdf = PinkCyberPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Document Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(43, 17, 48)
    pdf.cell(0, 8, "EXECUTIVE AUDIT SUMMARY", ln=True)
    pdf.ln(2)

    # Metadata Grid
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(50, 6, "Target URL:", 0, 0)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(255, 79, 163)
    pdf.cell(0, 6, str(scan_data.get("url", ""))[:65], ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(50, 6, "Primary IP & Domain:", 0, 0)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, f"{scan_data.get('primary_ip', '')} ({scan_data.get('domain', '')})", ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(50, 6, "Scan Timestamp:", 0, 0)
    pdf.cell(0, 6, str(scan_data.get("timestamp", "")), ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(50, 6, "HTTP Response Status:", 0, 0)
    pdf.cell(0, 6, f"{scan_data.get('status_code', 0)} ({scan_data.get('response_time', 0)}s)", ln=True)
    pdf.ln(6)

    # Core Metric Badges
    pdf.set_fill_color(255, 240, 246)
    pdf.set_draw_color(255, 79, 163)
    pdf.rect(10, pdf.get_y(), 60, 20, "DF")
    pdf.rect(75, pdf.get_y(), 60, 20, "DF")
    pdf.rect(140, pdf.get_y(), 60, 20, "DF")

    curr_y = pdf.get_y()
    pdf.set_xy(10, curr_y + 2)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(60, 5, "SEO Score", 0, 1, "C")
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(255, 79, 163)
    pdf.cell(60, 7, f"{scan_data.get('seo_score', 0)} / 100", 0, 0, "C")

    pdf.set_xy(75, curr_y + 2)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(60, 5, "Security Coverage", 0, 1, "C")
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(255, 79, 163)
    pdf.cell(60, 7, f"{scan_data.get('security_coverage', 0)}%", 0, 0, "C")

    pdf.set_xy(140, curr_y + 2)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(60, 5, "Performance Time", 0, 1, "C")
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(255, 79, 163)
    pdf.cell(60, 7, f"{scan_data.get('response_time', 0)}s", 0, 1, "C")
    pdf.ln(12)

    # Section 1: Security Headers Audit
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(84, 38, 94)
    pdf.cell(0, 8, "1. SECURITY HEADERS EVALUATION", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(40, 40, 40)

    for h in scan_data.get("security", {}).get("headers", []):
        status_txt = "[PASS]" if h.get("present") else "[MISSING]"
        color = (34, 197, 94) if h.get("present") else (239, 68, 68)
        pdf.set_text_color(*color)
        pdf.cell(24, 6, status_txt, 0, 0)
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(65, 6, h.get("name", ""), 0, 0)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(0, 6, h.get("description", "")[:60], ln=True)
    pdf.ln(4)

    # Section 2: SEO Checklist
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(84, 38, 94)
    pdf.cell(0, 8, "2. SEO ESSENTIALS CHECKLIST", ln=True)

    for chk in scan_data.get("seo", {}).get("checklist", []):
        stat = chk.get("status", "pass")
        color = (34, 197, 94) if stat == "pass" else ((234, 179, 8) if stat == "warn" else (239, 68, 68))
        pdf.set_text_color(*color)
        pdf.cell(20, 6, f"[{stat.upper()}]", 0, 0)
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(50, 6, chk.get("item", ""), 0, 0)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(0, 6, chk.get("note", "")[:70], ln=True)
    pdf.ln(4)

    # Section 3: Detected Technologies
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(84, 38, 94)
    pdf.cell(0, 8, "3. DETECTED TECHNOLOGY STACK", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(50, 50, 50)

    techs = scan_data.get("tech_stack", [])
    if techs:
        for t in techs:
            pdf.cell(50, 5, f"- {t.get('name')}", 0, 0)
            pdf.cell(45, 5, f"Category: {t.get('category')}", 0, 0)
            pdf.cell(0, 5, f"Confidence: {t.get('confidence')}", ln=True)
    else:
        pdf.cell(0, 5, "No specific technology signatures detected.", ln=True)
    pdf.ln(6)

    # Section 4: Actionable Recommendations
    pdf.set_x(10)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(84, 38, 94)
    pdf.cell(0, 8, "4. ACTIONABLE HARDENING ROADMAP", ln=True)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(60, 60, 60)

    recs = scan_data.get("security", {}).get("recommendations", []) + scan_data.get("performance", {}).get("recommendations", [])
    if recs:
        for i, rec in enumerate(recs[:8], 1):
            pdf.set_x(10)
            pdf.multi_cell(190, 5, f"{i}. {rec}")
    else:
        pdf.set_x(10)
        pdf.cell(0, 5, "Semua konfigurasi utama telah memenuhi standar best-practice.", ln=True)

    return pdf.output()
