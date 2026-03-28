
🔐 Cyber Risk Assessment & Threat Intelligence Platform
📌 Overview

This project is a Python-based platform designed to perform automated cyber risk assessment and integrate threat intelligence. It scans a target (IP/domain), identifies open ports, analyzes potential threats, and calculates a risk score with actionable recommendations.

The system combines:

  🔍 Network scanning (Nmap)
  🌐 Threat intelligence (VirusTotal API)
  📊 Risk scoring engine
  📈 Interactive dashboard (Streamlit)

🖥️ Home / Dashboard Preview
  <p align="center">
  <img src="Final_project/dashboard.png" width="800"/>
</p>

    
📂 Project Structure

CyberScan/

├── scanner.py          # Nmap-based port scanning
├── threat_intel.py     # VirusTotal API integration
├── risk_engine.py      # Risk calculation logic
├── api.py              # FastAPI backend
├── dashboard.py        # Streamlit dashboard
├── cyberscan.db        # SQLite database
└── README.md           # Project documentation

⚙️ Features

    🔍 Fast network scanning using Nmap
    🌐 Threat intelligence using VirusTotal API
    📊 Risk scoring system (Low / Medium / High / Critical)
    📈 Interactive dashboard (charts, heatmaps, metrics)
    📄 PDF report generation
    📧 Email alerts for high-risk targets
    🕘 Scan history tracking
    
🧠 Modules Description

1. scanner.py

Performs fast and fallback scans using Nmap to detect open ports.

2. threat_intel.py

Fetches threat data such as malicious/suspicious counts from VirusTotal.

3. risk_engine.py

Calculates final risk score based on:
    Exposure (open ports)
    Threat intelligence
    Context score
   
5. api.py

Handles backend operations using FastAPI:
    Scan requests
    Data storage
    Result retrieval
   
5. app.py

Streamlit-based dashboard for:
    Running scans
    Visualizing results
    Downloading reports
   
🚀 How to Run

    1. Install dependencies
          pip install -r requirements.txt
    2. Run Backend (optional)
          uvicorn api:app --reload
    3. Run Dashboard
          streamlit run app.py
          
🔑 Requirements

        Python 3.x
        Nmap installed
        VirusTotal API key 
        
📊 Risk Calculation Logic

Risk Score is calculated using:

    Exposure Score → Based on open ports
    Threat Score → From VirusTotal
    Context Score → Default baseline

🎯 Targets Used

        Public IP addresses
        Test domains
        Localhost / private networks (for safe testing)

⚠️ Note: Only scan systems you have permission to test.



👤 Author
Anakala Harshitha
