import sqlite3
from pathlib import Path
from datetime import datetime

DB = Path(__file__).resolve().parents[2] / "aerodrift.db"

def connect():
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        drift_type TEXT,
        severity TEXT,
        resource TEXT,
        action TEXT,
        status TEXT
    )""")
    con.commit()
    return con

def log_incident(drift_type, severity, resource, action, status):
    con = connect()
    con.execute("INSERT INTO incidents(timestamp,drift_type,severity,resource,action,status) VALUES(?,?,?,?,?,?)",
                (datetime.now().isoformat(timespec="seconds"), drift_type, severity, resource, action, status))
    con.commit()
    con.close()

def history():
    con = connect()
    rows = con.execute("SELECT id,timestamp,drift_type,severity,resource,action,status FROM incidents ORDER BY id DESC").fetchall()
    con.close()
    return rows
