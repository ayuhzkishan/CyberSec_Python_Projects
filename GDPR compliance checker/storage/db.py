import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict
from urllib.parse import urlparse

DB_PATH = Path("gdpr_crawler.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            cookie_banner INTEGER,
            banner_selector TEXT,
            privacy_policy TEXT,
            privacy_policy_html TEXT,
            html_path TEXT,
            screenshot_base64 TEXT,
            error TEXT,
            compliance_score TEXT,
            clause_results TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_scan(scan_data: Dict, clause_results: Dict, compliance_score: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    domain = urlparse(scan_data.get("url", "")).netloc
    
    cursor.execute("""
        INSERT INTO scans (url, domain, timestamp, cookie_banner, banner_selector, privacy_policy,
                          privacy_policy_html, html_path, screenshot_base64, error,
                          compliance_score, clause_results)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_data.get("url"),
        domain,
        scan_data.get("timestamp"),
        int(scan_data.get("cookie_banner", False)),
        scan_data.get("banner_selector"),
        scan_data.get("privacy_policy"),
        scan_data.get("privacy_policy_html"),
        scan_data.get("html_path"),
        scan_data.get("screenshot_base64"),
        scan_data.get("error"),
        compliance_score,
        json.dumps(clause_results)
    ))
    
    scan_id = cursor.lastrowid or 0
    conn.commit()
    conn.close()
    return scan_id


def get_all_scans() -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    
    conn.close()
    return [dict(row) for row in rows]


def get_scan_with_results(scan_id: int) -> Optional[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = cursor.fetchone()
    
    if not scan:
        conn.close()
        return None
    
    scan_dict = dict(scan)
    if scan_dict.get("clause_results"):
        scan_dict["clause_results"] = json.loads(scan_dict["clause_results"])
    
    conn.close()
    return scan_dict


def get_scans_by_domain(domain: str) -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM scans WHERE domain = ? ORDER BY timestamp DESC", (domain,))
    rows = cursor.fetchall()
    
    conn.close()
    return [dict(row) for row in rows]


def get_latest_scan_per_domain() -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT s.* FROM scans s
        INNER JOIN (
            SELECT domain, MAX(timestamp) as max_timestamp
            FROM scans
            GROUP BY domain
        ) latest ON s.domain = latest.domain AND s.timestamp = latest.max_timestamp
        ORDER BY s.timestamp DESC
    """)
    rows = cursor.fetchall()
    
    conn.close()
    return [dict(row) for row in rows]
