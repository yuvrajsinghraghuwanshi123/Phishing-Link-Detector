
import sqlite3
import json
from pathlib import Path
from datetime import datetime
from contextlib import closing


DB_PATH = Path(__file__).with_name("scan_history.db")


def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    hostname TEXT,
                    risk_score INTEGER,
                    risk_level TEXT,
                    reasons TEXT,
                    analysis_data TEXT,
                    scanned_at TEXT
                )
            """)


def save_scan(analysis, risk):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        with conn:
            cursor = conn.execute("""
                INSERT INTO scan_history
                (url, hostname, risk_score, risk_level,
                 reasons, analysis_data, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis["url"],
                analysis["hostname"],
                risk["score"],
                risk["level"],
                json.dumps(risk["reasons"]),
                json.dumps(analysis),
                datetime.now().astimezone().isoformat(timespec="seconds")
            ))

            return cursor.lastrowid



def get_scan_history(limit=50):

    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("Limit must be a positive integer")

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT * FROM scan_history
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        history = [dict(row) for row in rows]

        for scan in history:
            scan["reasons"] = json.loads(scan["reasons"])
            scan["analysis_data"] = json.loads(scan["analysis_data"])

        return history

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully!")