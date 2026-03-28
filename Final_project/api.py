from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import re
import json
import os

from scanner import run_nmap_scan
from threat_intel import get_virustotal_data
from risk_engine import calculate_risk

app = FastAPI()

DB_NAME = "cyberscan.db"


# ---------------- DATABASE ---------------- #
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        ports TEXT,
        threat_score REAL,
        risk_score REAL,
        severity TEXT
    )
    """)

    conn.commit()
    conn.close()


init_db()


# ---------------- VALIDATION ---------------- #
def validate_target(target: str):
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    domain_regex = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if not re.match(ip_regex, target) and not re.match(domain_regex, target):
        raise HTTPException(status_code=400, detail="Invalid IP or domain")


# ---------------- MODEL ---------------- #
class ScanRequest(BaseModel):
    target: str


# ---------------- API ---------------- #

@app.get("/")
def home():
    return {"message": "Cyber Risk Assessment API Running 🚀"}


@app.post("/scan")
def scan_target(request: ScanRequest):
    target = request.target.strip()

    # ✅ Validate input
    validate_target(target)

    try:
        # ---------------- STEP 1: SCAN ---------------- #
        scan_data = run_nmap_scan(target)

        # ---------------- STEP 2: THREAT ---------------- #
        api_key = os.getenv("VT_API_KEY")  # set in environment
        threat_data = get_virustotal_data(target, api_key)

        # ---------------- STEP 3: RISK ---------------- #
        risk = calculate_risk(scan_data, threat_data)

        # ---------------- STEP 4: STORE ---------------- #
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO scans (ip, ports, threat_score, risk_score, severity)
        VALUES (?, ?, ?, ?, ?)
        """, (
            target,
            json.dumps(scan_data.get("ports", [])),  # ✅ proper storage
            threat_data.get("threat_score", 0),
            risk.get("risk_score", 0),
            risk.get("severity", "Unknown")
        ))

        conn.commit()
        conn.close()

        # ---------------- RESPONSE ---------------- #
        return {
            "target": target,
            "scan": scan_data,
            "threat": threat_data,
            "risk": risk
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/results")
def get_results():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans ORDER BY id DESC")
        rows = cursor.fetchall()

        conn.close()

        # ✅ Format output cleanly
        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "ip": row[1],
                "ports": json.loads(row[2]),
                "threat_score": row[3],
                "risk_score": row[4],
                "severity": row[5]
            })

        return {"data": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/results/{ip}")
def get_results_by_ip(ip: str):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans WHERE ip = ?", (ip,))
        rows = cursor.fetchall()

        conn.close()

        if not rows:
            raise HTTPException(status_code=404, detail="No data found")

        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "ip": row[1],
                "ports": json.loads(row[2]),
                "threat_score": row[3],
                "risk_score": row[4],
                "severity": row[5]
            })

        return {"data": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))