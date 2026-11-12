"""
PINK WEB SCANNER - DATABASE MODULE
Handles SQLite database persistence, history, favorites, settings, and statistical aggregations.
Uses parameterized queries to ensure security.
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pink_scanner.db")

def get_connection():
    """Returns a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes tables if they do not exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                timestamp DATETIME NOT NULL,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                status_code INTEGER,
                seo_score INTEGER DEFAULT 0,
                security_coverage REAL DEFAULT 0.0,
                response_time REAL DEFAULT 0.0,
                raw_json TEXT NOT NULL,
                is_favorite INTEGER DEFAULT 0
            )
        """)
        
        # Favorites table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS favorites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                title TEXT,
                notes TEXT,
                created_at DATETIME NOT NULL
            )
        """)
        
        # Settings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        
        # Performance indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")
        conn.commit()

def save_scan(scan_data: Dict[str, Any]) -> str:
    """Saves a completed scan result into the database."""
    init_db()
    scan_id = scan_data.get("scan_id", datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
    timestamp = scan_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    url = scan_data.get("url", "")
    domain = scan_data.get("domain", "")
    status_code = scan_data.get("status_code", 0)
    seo_score = scan_data.get("seo_score", 0)
    security_coverage = scan_data.get("security_coverage", 0.0)
    response_time = scan_data.get("response_time", 0.0)
    raw_json = json.dumps(scan_data, ensure_ascii=False)
    
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO scans 
            (scan_id, timestamp, url, domain, status_code, seo_score, security_coverage, response_time, raw_json, is_favorite)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """, (scan_id, timestamp, url, domain, status_code, seo_score, security_coverage, response_time, raw_json))
        conn.commit()
    return scan_id

def get_scan_history(limit: int = 50, search_query: str = "", date_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves list of scans filtered by search keyword and date."""
    init_db()
    query = "SELECT id, scan_id, timestamp, url, domain, status_code, seo_score, security_coverage, response_time, is_favorite FROM scans WHERE 1=1"
    params = []
    
    if search_query:
        query += " AND (url LIKE ? OR domain LIKE ?)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])
        
    if date_filter:
        query += " AND DATE(timestamp) = DATE(?)"
        params.append(date_filter)
        
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    """Loads complete scan data by scan_id."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT raw_json FROM scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        if row and row["raw_json"]:
            return json.loads(row["raw_json"])
    return None

def delete_scan(scan_id: str) -> bool:
    """Deletes a single scan by scan_id."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0

def clear_all_scans() -> bool:
    """Deletes all scan records safely."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans")
        conn.commit()
        return True

def toggle_favorite(scan_id: str) -> bool:
    """Toggles favorite state of a scan."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT is_favorite, url, domain FROM scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return False
        new_state = 0 if row["is_favorite"] == 1 else 1
        cursor.execute("UPDATE scans SET is_favorite = ? WHERE scan_id = ?", (new_state, scan_id))
        conn.commit()
        return bool(new_state)

def get_overview_stats() -> Dict[str, Any]:
    """Calculates summary KPIs and activity metrics for Overview Dashboard."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Total counts
        cursor.execute("SELECT COUNT(*) as total FROM scans")
        total_scans = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as success FROM scans WHERE status_code >= 200 AND status_code < 400")
        success_scans = cursor.fetchone()["success"]
        
        failed_scans = total_scans - success_scans
        
        # Averages
        cursor.execute("""
            SELECT 
                AVG(seo_score) as avg_seo,
                AVG(response_time) as avg_resp_time,
                AVG(security_coverage) as avg_sec_coverage
            FROM scans WHERE status_code > 0
        """)
        avg_row = cursor.fetchone()
        avg_seo = round(avg_row["avg_seo"] or 0, 1)
        avg_resp_time = round(avg_row["avg_resp_time"] or 0, 3)
        avg_sec_coverage = round(avg_row["avg_sec_coverage"] or 0, 1)
        
        # Daily activity for last 7 days
        cursor.execute("""
            SELECT DATE(timestamp) as scan_date, COUNT(*) as count 
            FROM scans 
            GROUP BY DATE(timestamp) 
            ORDER BY scan_date DESC 
            LIMIT 7
        """)
        activity_rows = cursor.fetchall()
        daily_activity = [{"date": r["scan_date"], "count": r["count"]} for r in reversed(activity_rows)]
        
        # Status distribution
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN status_code >= 200 AND status_code < 300 THEN '2xx Success'
                    WHEN status_code >= 300 AND status_code < 400 THEN '3xx Redirect'
                    WHEN status_code >= 400 AND status_code < 500 THEN '4xx Client Error'
                    WHEN status_code >= 500 THEN '5xx Server Error'
                    ELSE 'Failed / Unreachable'
                END as status_group,
                COUNT(*) as count
            FROM scans
            GROUP BY status_group
        """)
        status_dist_rows = cursor.fetchall()
        status_dist = [{"status": r["status_group"], "count": r["count"]} for r in status_dist_rows]
        
    return {
        "total_scans": total_scans,
        "success_scans": success_scans,
        "failed_scans": failed_scans,
        "avg_seo": avg_seo,
        "avg_resp_time": avg_resp_time,
        "avg_sec_coverage": avg_sec_coverage,
        "daily_activity": daily_activity,
        "status_distribution": status_dist
    }

def save_setting(key: str, value: str):
    """Saves a key-value setting."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()

def get_setting(key: str, default: str = "") -> str:
    """Reads a setting value."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row["value"] if row else default
