
🔐 Cyber Risk Assessment & Threat Intelligence Platform
📌 Overview

This project is a Python-based Cyber Risk Assessment Platform that automates vulnerability scanning and integrates threat intelligence to evaluate system security.It scans a given IP address or domain, detects open ports, analyzes potential threats, and computes a risk score with actionable recommendations.

🖥️ Home / Dashboard Preview

<img width="1919" height="1072" alt="dashboard1" src="https://github.com/user-attachments/assets/55b2c7b4-5fd8-4029-8a9c-41618a8057c9" />



🔧 Technologies Used:

    🔍 Network Scanning – Nmap

    🌐 Threat Intelligence – VirusTotal API

    📊 Risk Analysis Engine

    📈 Dashboard – Streamlit

    ⚡ Backend – 

        🗄 Database – SQLite

📂 Project Structure
CyberScan/

    ├── scanner.py          # Nmap-based port scanning
    ├── threat_intel.py     # VirusTotal API integration
    ├── risk_engine.py      # Risk calculation logic
    ├── api.py              # FastAPI backend
    ├── app.py              # Streamlit dashboard
    ├── cyberscan.db        # SQLite database
    └── README.md           # Project documentation

⚙️ Features
    
    🔍 Fast network scanning using Nmap
    🌐 Threat intelligence integration (VirusTotal API)
    📊 Risk scoring system (Low / Medium / High / Critical)
    📈 Interactive dashboard (charts, heatmaps, metrics)
    📄 PDF report generation
    📧 Email alerts for high-risk targets
    🕘 Scan history tracking

🧠 Modules Description

    1. scanner.py
        Performs fast and fallback scans using Nmap
        Identifies open ports on the target system
    2. threat_intel.py
        Fetches threat intelligence data from VirusTotal
        Analyzes malicious and suspicious activity
    3. risk_engine.py
        Calculates final risk score based on:
        Exposure (open ports)
        Threat intelligence
        Context score
    4. api.py
        Built using FastAPI
        Handles:
            Scan requests
            Data storage
            Result retrieval
    5. app.py
        Streamlit-based dashboard
        Provides:
            Scan execution
            Data visualization
            Report download

🚀 How to Run

    1️⃣ Install Dependencies
            pip install -r requirements.txt
    2️⃣ Run Backend (Optional)
            uvicorn api:app --reload
    3️⃣ Run Dashboard
            streamlit run app.py

🔑 Requirements
  
    Python 3.x
    Nmap installed
    VirusTotal API Key

📊 Risk Calculation Logic

    The Risk Score (0–10) is computed using:
        Exposure Score → Based on number of open ports
        Threat Score → Derived from VirusTotal data
        Context Score → Default baseline factor
        🧮 Formula:
              Risk Score = (0.5 × Exposure) + (0.3 × Threat) + (0.2 × Context)
              
🎯 Targets Used

    Public IP addresses
    Test domains
    Localhost / private networks (safe testing)

⚠️ Disclaimer

⚠️ This tool is intended for educational and authorized security testing only.
Do NOT scan systems without proper permission.

------------------------------------------------------------------------------------------------

👩‍💻 Author

Anakala Harshitha
