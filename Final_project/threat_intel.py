import requests


def get_virustotal_data(ip, api_key=None):
    _default = {
        "source": "VirusTotal",
        "available": False,
        "malicious_count": 0,
        "suspicious_count": 0,
        "harmless_count": 0,
        "threat_score": 1,
        "score": 1,  # ✅ ADD THIS
        "note": "No API key or failed request"
    }

    if not api_key:
        return {
            **_default,
            "note": "No API key provided"
        }

    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": api_key}

        response = requests.get(url, headers=headers, timeout=3)

        if response.status_code != 200:
            return {
                **_default,
                "note": f"VT API error {response.status_code}"
            }

        data = response.json()

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))

        threat_score = min((malicious * 2) + suspicious, 10)

        return {
            "source": "VirusTotal",
            "available": True,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "threat_score": threat_score,
            "score": threat_score  # ✅ FIXED
        }

    except requests.exceptions.Timeout:
        return {**_default, "note": "VT request timeout"}

    except Exception as e:
        return {**_default, "error": str(e)}