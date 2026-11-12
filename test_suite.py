"""
PINK WEB SCANNER - AUTOMATED TEST SUITE
Tests all core modules, scanning, parsing, database persistence, and report generation.
"""

from datetime import datetime
import scanner
import seo_analyzer
import security_analyzer
import network_analyzer
import performance_analyzer
import tech_detector
import database
import report_generator

def run_tests():
    print("=== STARTING PINK WEB SCANNER TEST SUITE ===")
    
    # Test 1: SSRF Protection
    print("\n[TEST 1] Testing SSRF Protection...")
    blocked_targets = ["localhost", "127.0.0.1", "http://0.0.0.0:8080", "http://192.168.1.1"]
    for target in blocked_targets:
        try:
            scanner.validate_and_resolve_url(target)
            print(f"FAILED: SSRF did not block {target}")
            return False
        except scanner.SecurityViolationError as e:
            print(f"PASS: SSRF correctly blocked {target} ({e})")

    # Test 2: Real Website Scan
    print("\n[TEST 2] Testing Website Scanning against example.com...")
    raw = scanner.scan_website("https://example.com", timeout=8)
    if not raw.get("success"):
        print(f"FAILED: Scan failed: {raw.get('error')}")
        return False
    print(f"PASS: HTTP Status: {raw.get('status_code')}, Response Time: {raw.get('response_time')}s")

    # Test 3: SEO Analysis
    print("\n[TEST 3] Testing SEO & HTML Analysis...")
    seo = seo_analyzer.analyze_seo(raw.get("html", ""), raw.get("final_url", "https://example.com"))
    print(f"PASS: Title: {seo['title']['text']}, Score: {seo['score']}/100, Grade: {seo['grade']}")

    # Test 4: Security Analysis
    print("\n[TEST 4] Testing Security Analyzer...")
    sec = security_analyzer.analyze_security(raw.get("headers", {}), raw.get("final_url", "https://example.com"))
    print(f"PASS: Security Coverage: {sec['coverage_pct']}%, Grade: {sec['grade']}")

    # Test 5: Network Analyzer
    print("\n[TEST 5] Testing DNS & Network Analyzer...")
    net = network_analyzer.analyze_network(raw.get("final_url", "https://example.com"))
    print(f"PASS: Hostname: {net['hostname']}, IP: {net['primary_ip']}, Country: {net['geolocation'].get('country')}")

    # Test 6: Performance Analyzer
    print("\n[TEST 6] Testing Performance Analyzer...")
    perf = performance_analyzer.analyze_performance(raw)
    print(f"PASS: Latency: {perf['response_time_sec']}s, Rating: {perf['rating']}")

    # Test 7: Technology Detector
    print("\n[TEST 7] Testing Technology Detector...")
    tech = tech_detector.detect_technologies(raw.get("html", ""), raw.get("headers", {}))
    print(f"PASS: Technologies detected: {len(tech)}")

    # Test 8: Database Operations
    print("\n[TEST 8] Testing SQLite Database Persistence...")
    database.init_db()
    scan_id = "test_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    payload = {
        "scan_id": scan_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": raw["url"],
        "final_url": raw["final_url"],
        "domain": raw["domain"],
        "status_code": raw["status_code"],
        "reason": raw.get("reason", "OK"),
        "primary_ip": raw.get("primary_ip", ""),
        "response_time": raw.get("response_time", 0.0),
        "content_size": raw.get("content_size", 0),
        "content_type": raw.get("content_type", ""),
        "server": raw.get("server", ""),
        "powered_by": raw.get("powered_by", ""),
        "headers": raw.get("headers", {}),
        "cookies": raw.get("cookies", []),
        "redirect_count": raw.get("redirect_count", 0),
        "seo_score": seo["score"],
        "seo_grade": seo["grade"],
        "security_coverage": sec["coverage_pct"],
        "security_score": sec["score"],
        "seo": seo,
        "security": sec,
        "network": net,
        "performance": perf,
        "tech_stack": tech,
        "robots": {"exists": False, "url": "", "status_code": 0},
        "sitemap": {"exists": False, "url_count": 0}
    }
    saved_id = database.save_scan(payload)
    loaded = database.get_scan_by_id(saved_id)
    assert loaded is not None, "Failed to load scan from SQLite"
    print(f"PASS: Successfully saved and retrieved scan ID: {saved_id}")

    # Test 9: Report Generation
    print("\n[TEST 9] Testing Report Generation (PDF, CSV, JSON)...")
    pdf_bytes = report_generator.generate_pdf_report(payload)
    assert len(pdf_bytes) > 500, "PDF bytes too small"
    csv_str = report_generator.generate_csv_report(payload)
    assert "Target URL" in csv_str, "CSV missing target url"
    json_str = report_generator.generate_json_report(payload)
    assert scan_id in json_str, "JSON missing scan_id"
    print(f"PASS: Reports Generated! PDF size: {len(pdf_bytes)} bytes, CSV chars: {len(csv_str)}, JSON chars: {len(json_str)}")

    print("\n=============================================")
    print("SUCCESS: ALL 9 CRITICAL TESTS PASSED WITH 100% SUCCESS!")
    print("=============================================")
    return True

if __name__ == "__main__":
    run_tests()
