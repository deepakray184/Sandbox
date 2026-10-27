import sqlite3
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from app.core.config import DB_PATH

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS submissions (
            id TEXT PRIMARY KEY,
            target_type TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            sha256 TEXT,
            verdict TEXT DEFAULT 'Pending',
            threat_score INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            tags TEXT DEFAULT '[]',
            summary TEXT DEFAULT '',
            report_data TEXT DEFAULT '{}'
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyst_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id TEXT NOT NULL,
            author TEXT NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(submission_id) REFERENCES submissions(id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    conn.close()

def save_submission(
    sub_id: str,
    target_type: str,
    filename: str,
    file_size: int,
    sha256: str,
    verdict: str,
    threat_score: int,
    tags: List[str],
    summary: str,
    report_data: Dict[str, Any]
):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat() + "Z"
    cursor.execute("""
        INSERT OR REPLACE INTO submissions 
        (id, target_type, filename, file_size, sha256, verdict, threat_score, created_at, tags, summary, report_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        sub_id,
        target_type,
        filename,
        file_size,
        sha256,
        verdict,
        threat_score,
        now,
        json.dumps(tags),
        summary,
        json.dumps(report_data)
    ))
    conn.commit()
    conn.close()

def get_submission(sub_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM submissions WHERE id = ?", (sub_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    res = dict(row)
    res['tags'] = json.loads(res['tags'] or '[]')
    res['report_data'] = json.loads(res['report_data'] or '{}')
    return res

def list_submissions(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, target_type, filename, file_size, sha256, verdict, threat_score, created_at, tags, summary FROM submissions ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    result = []
    for row in rows:
        item = dict(row)
        item['tags'] = json.loads(item['tags'] or '[]')
        result.append(item)
    return result

def get_stats() -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM submissions")
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM submissions WHERE verdict = 'Malicious'")
    malicious = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM submissions WHERE verdict = 'Suspicious'")
    suspicious = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM submissions WHERE verdict = 'Clean'")
    clean = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM submissions WHERE target_type = 'email'")
    emails = cursor.fetchone()[0]
    
    conn.close()
    return {
        "total_scans": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "clean": clean,
        "emails_analyzed": emails
    }

def add_analyst_note(submission_id: str, author: str, note: str):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat() + "Z"
    cursor.execute("INSERT INTO analyst_notes (submission_id, author, note, created_at) VALUES (?, ?, ?, ?)",
                   (submission_id, author, note, now))
    conn.commit()
    conn.close()

def get_analyst_notes(submission_id: str) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, author, note, created_at FROM analyst_notes WHERE submission_id = ? ORDER BY id ASC", (submission_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
