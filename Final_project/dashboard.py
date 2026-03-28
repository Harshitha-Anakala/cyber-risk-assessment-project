import streamlit as st
import sqlite3, json, re, smtplib
from email.mime.text import MIMEText
from io import BytesIO
from fpdf import FPDF
import pandas as pd
import plotly.express as px
import plotly.io as pio

from scanner import run_nmap_scan
from threat_intel import get_virustotal_data
from risk_engine import calculate_risk

# ---------------- CONFIG ---------------- #
st.set_page_config(page_title="CyberScan", layout="wide")
pio.templates.default = "plotly_dark"

DB_NAME = "cyberscan.db"

# ---------------- STYLING ---------------- #
st.markdown("""
<style>
div[data-testid="stMetric"] {
    background-color: #1e2a38;
    padding: 15px;
    border-radius: 10px;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

# ---------------- INIT DB ---------------- #
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
def validate_target(target):
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    domain_regex = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(ip_regex, target) or re.match(domain_regex, target)

# ---------------- EMAIL FUNCTION ---------------- #
def send_email_alert(to_email, target, risk):
    try:
        html = f"""
        <h2>🚨 Cyber Risk Alert</h2>
        <p><b>Target:</b> {target}</p>
        <p><b>Risk Score:</b> {risk.get('risk_score')}</p>
        <p><b>Severity:</b> {risk.get('severity')}</p>
        <ul>
            {''.join(f"<li>{r}</li>" for r in risk.get('recommendations', []))}
        </ul>
        """

        msg = MIMEText(html, "html")
        msg["Subject"] = "Cyber Risk Alert"
        msg["From"] = "your_email@gmail.com"
        msg["To"] = to_email

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login("your_email@gmail.com", "your_app_password")
            server.send_message(msg)

    except Exception as e:
        st.warning(f"Email failed: {e}")

# ---------------- SESSION ---------------- #
if "last_scan" not in st.session_state:
    st.session_state.last_scan = None

# ---------------- SIDEBAR ---------------- #
st.sidebar.title("🔐 CyberScan")

page = st.sidebar.radio("Navigate", ["Dashboard", "Details", "History"])
target = st.sidebar.text_input("Target (IP / Domain)")
email = st.sidebar.text_input("📧 Email Alert (optional)")
vt_api_key = st.sidebar.text_input("🔑 VirusTotal API Key", type="password")

run_scan = st.sidebar.button("🚀 Run Scan")

# ---------------- RUN SCAN ---------------- #
if run_scan:
    if not target or not validate_target(target):
        st.error("Invalid target")
    else:
        # Loading UI
        st.info("Running vulnerability scan...")
        scan_data = run_nmap_scan(target)

        st.info("Fetching threat intelligence...")
        threat_data = get_virustotal_data(target, vt_api_key)

        st.info("Calculating risk score...")
        risk = calculate_risk(scan_data, threat_data)

        # Save session
        st.session_state.last_scan = {
            "target": target,
            "scan": scan_data,
            "risk": risk
        }

        # Save to DB
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()

            ports = scan_data.get("ports", [])
            threat_score = threat_data.get("threat_score", 0)
            risk_score = risk.get("risk_score", 0)
            severity = risk.get("severity", "Unknown")

            cursor.execute("""
                INSERT INTO scans (ip, ports, threat_score, risk_score, severity)
                VALUES (?, ?, ?, ?, ?)
            """, (
                target,
                json.dumps(ports),
                threat_score,
                risk_score,
                severity
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            st.error(f"Database error: {e}")

        st.success("✔ Scan Completed Successfully")

        # ✅ EMAIL ALERT
        if email and risk.get("severity") in ["High", "Critical"]:
            send_email_alert(email, target, risk)

# ---------------- DASHBOARD ---------------- #
if page == "Dashboard":
    st.title("Cyber Risk Assessment & Threat Intelligence Platform")
    st.markdown("Scan targets, assess cyber risk, view threat intelligence, and generate security reports.")

    data = st.session_state.get("last_scan")

    if data:
        ports = data["scan"].get("ports", [])
        risk = data["risk"]

        # Metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Open Ports", len(ports))
        col2.metric("Threat Score", risk.get("threat_score", 0))
        col3.metric("Final Risk Score", risk.get("risk_score", 0))

        # Risk Breakdown
        st.subheader("⚡ Risk Score Breakdown")
        breakdown = pd.DataFrame({
            "Component":["Exposure","Threat","Context"],
            "Score":[risk.get("exposure_score",0), risk.get("threat_score",0), 5]
        })

        fig_breakdown = px.bar(
            breakdown,
            x="Component",
            y="Score",
            color="Component",
            color_discrete_map={
                "Exposure": "#FF6B6B",
                "Threat": "#FFA500",
                "Context": "#4CAF50"
            }
        )
        st.plotly_chart(fig_breakdown, use_container_width=True)

        # Open Ports
        st.subheader("🛡 Open Ports")
        ports_df = pd.DataFrame({"Port": ports})
        if not ports_df.empty:
            fig_ports = px.histogram(
                ports_df,
                x="Port",
                nbins=len(ports),
                color_discrete_sequence=["#00BCD4"]
            )
            st.plotly_chart(fig_ports, use_container_width=True)

        # Heatmap
        st.subheader("🌡 Open Ports Heatmap")
        if ports:
            heatmap_df = pd.DataFrame({"Port": ports, "Count":[1]*len(ports)})
            heatmap_pivot = heatmap_df.pivot_table(index="Port", values="Count", aggfunc="sum")

            fig_heatmap = px.imshow(
                [heatmap_pivot["Count"].values],
                color_continuous_scale="Reds"
            )
            st.plotly_chart(fig_heatmap, use_container_width=True)

        # Donut Chart
        st.subheader("🎯 Severity Distribution")
        severity_df = pd.DataFrame({
            "Severity":[risk.get("severity")],
            "Count":[1]
        })

        fig_donut = px.pie(
            severity_df,
            names='Severity',
            values='Count',
            hole=0.6,
            color='Severity',
            color_discrete_map={
                "Low": "#00E676",
                "Medium": "#FFEA00",
                "High": "#FF9100",
                "Critical": "#FF1744"
            }
        )

        fig_donut.update_traces(
            textinfo='percent+label',
            pull=[0.08],
            marker=dict(line=dict(color='#000000', width=2))
        )

        st.plotly_chart(fig_donut, use_container_width=True)

    else:
        st.info("Run a scan to see dashboard")

# ---------------- DETAILS ---------------- #
elif page == "Details":
    st.title("🔍 Scan Details")
    data = st.session_state.get("last_scan")

    if data:
        st.write("### Target:", data["target"])
        st.write("### Open Ports:", data["scan"].get("ports", []))
        st.json(data["risk"])
    else:
        st.warning("No scan available")

# ---------------- HISTORY ---------------- #
elif page == "History":
    st.title("🕘 Scan History")

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()

        if rows:
            history = []
            for r in rows:
                try:
                    ports = json.loads(r[2])
                except:
                    ports = []

                history.append({
                    "IP": r[1],
                    "Ports": len(ports),
                    "Threat": r[3],
                    "Risk": r[4],
                    "Severity": r[5]
                })

            st.dataframe(pd.DataFrame(history))
        else:
            st.info("No history yet")

    except Exception as e:
        st.error(f"History error: {e}")