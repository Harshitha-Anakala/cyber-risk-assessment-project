import requests
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
data = requests.get(url).json()
print(type(data))
print(data.keys())

# 1.Extracting only objects where type == "attack-pattern"
techniques = []
for obj in data["objects"]:
    if obj.get("type") == "attack-pattern":
        techniques.append(obj)
print("Total attack techniques present are: ", len(techniques))

# 2. Building Threat Scoring Logic
def threat_score(tech):
    score = 5 
    name = tech.get("name", "").lower()
    description = tech.get("description", "").lower()
    
    if "credential" in name:
        score += 3
    if "execution" in name:
        score += 2
    if "privilege" in name:
        score += 3
    if "persistence" in name:
        score += 2
    if "lateral" in name:
        score += 2

    if "administrator" in description:
        score += 2
    if "remote" in description:
        score += 2
    if "bypass" in description:
        score += 2
    if "stealth" in description:
        score += 1
    return score
print(threat_score(techniques[0]))

# 3. Scoring All Techniques
scored_techniques = []
for tech in techniques:
    score = threat_score(tech)
    scored_techniques.append((tech.get("name"), score))
    
# 4. Sort Techniques by Score
scored_techniques.sort(key=lambda x: x[1], reverse=True)
print("Top 10 Threats are:")
for name, score in scored_techniques[:10]:
    print(f"{name} — Score: {score}")

# 5. Critical Threat Filter (score ≥ 8.9)
print("\nCritical Threats:")
for name, score in scored_techniques:
    if score >= 8.9:
        print(f"{name}-{score}")
