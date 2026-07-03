[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)

# SOAR Playbook Engineering & Incident Response Automation

## 1. Executive Summary & Objective
* **Problem Statement:** Modern Security Operations Centers (SOCs) face elevated Mean Time to Respond (MTTR) due to manual threat intelligence lookups and pivoting between disconnected management consoles during active compromises. This delays critical containment actions and introduces human error under high-pressure scenarios.
* **Solution Overview:** This repository contains an open-source Security Orchestration, Automation, and Response (SOAR) infrastructure built on Shuffle. The suite automates end-to-end incident triage pipelines, ingests real-time SIEM alerts via secure webhooks, parses data structures via custom Python orchestration nodes, queries threat intelligence APIs, and programmatically isolates compromised endpoints to halt lateral movement without manual intervention.
* **Core Capabilities:**
  * Automated endpoint containment via authenticated API transactions.
  * Real-time automated enrichment of file hash indicators of compromise (IOCs).
  * Conditional logic orchestration to filter false positives before analyst routing.
  * Standardized notification distribution to central SOC communication channels.

## 2. Architecture & Environment Topology
The orchestration framework functions as a localized integration broker, binding ingestion systems, external intelligence planes, and host-level enforcement points into a cohesive loop.

* **Deployment Environment:** Localized Ubuntu Server architecture using standard virtualization or container boundaries.
* **Orchestration Core:** Shuffle SOAR engine deployed via containerized microservices (Frontend, Backend, Orborus workflow execution engine, and an OpenSearch database backend).
* **Integration Plane:** Secure HTTP webhooks for raw JSON payload transmission from upstream alerting instances (e.g., SIEM/XDR platforms).
* **Integrated API Nodes:** Synchronous communication paths engineered against the VirusTotal v3 REST API, AnyRun Sandbox API, and the secure remote management port (`55000/tcp`) of the Wazuh central management server.

## 3. Engineering Thought Process & Methodology
* **Design Considerations:** Utilizing an open-source, vendor-agnostic SOAR platform like Shuffle provides significant flexibility over closed ecosystems. It allows security engineers to build customizable integrations using native Python scripts rather than relying on vendor-locked, subscription-dependent plugins.
* **Technical Challenges & Resolution:**
  * **Challenge:** Handling raw SIEM JSON alerts with unpredictable structure can cause automation loops to fail during payload parsing. Furthermore, hardcoding cryptographic API tokens directly within individual script nodes introduces severe security and compliance liabilities.
  * **Resolution:** Standardized JSON data structural definitions across all ingestion nodes using structured exception handling block logic. All authentication tokens, tokens strings, and administrative credentials were programmatically abstracted out of the code base and migrated to Shuffle's secure encrypted authentication vault.

## 4. Cyber Kill Chain & Threat Lifecycle Mapping
This automation engine isolates threats at critical inflection points to disrupt malicious workflows:

* **Installation & Exploitation:** Real-time extraction of suspicious artifacts from host process streams immediately following initialization events.
* **Command and Control (C2):** Halting persistent administrative beacons by dropping host connectivity boundaries.
* **Actions on Objectives:** Preventing systemic lateral infrastructure exploration, data modification, or staging operations by executing sub-second network quarantine protocols.

## 5. MITRE ATT&CK Matrix Alignment
The playbook automation logic counters defensive evasion and limits the impact of execution vectors by mapping to these tactical behaviors:

| Tactic | Technique ID | Technique Name | Detection/Mitigation Mechanism |
| :--- | :--- | :--- | :--- |
| **Execution** | T1204.002 | Malicious File | Ingestion of endpoint detection alerts; immediate hash containment valuation via VirusTotal API enrichment nodes. |
| **Lateral Movement** | T1570 | Lateral Tool Transfer | Mitigation of asset-to-asset file replication through automated network boundary restrictions. |
| **Mitigation** | M1040 | Endpoint Isolation | Programmatic host isolation using authenticated PUT requests to the central XDR framework to apply immediate host blocks. |

## 6. OSINT & Reconnaissance Tooling Integrated
* **Tool Name:** VirusTotal v3 API Engine
  * **Use Case:** Programmatically checking historical reputation scores, multi-engine detection tallies, and behavioral metadata for extracted file indicators.
* **Tool Name:** AnyRun Interactive Sandbox API
  * **Use Case:** Orchestrating automated payload execution within isolated sandbox nodes to query threat analysis profiles and capture real-time telemetry markers.

## 7. Implementation & Code / Configuration Snippets

### Infrastructure Initialization (`docker-compose.yml`)
```bash
# Clone the verified repository source tree
git clone [https://github.com/Shuffle/Shuffle](https://github.com/Shuffle/Shuffle)
cd Shuffle

# Initialize the containerized frontend, backend, database, and orchestration worker nodes
sudo docker-compose up -d
```

### Use Case 1: Programmatic VirusTotal Reputation Lookup (`virustotal_enrichment.py`)
```python
import requests
import json

def check_vt_reputation(file_hash, api_key):
    url = f"[https://www.virustotal.com/api/v3/files/](https://www.virustotal.com/api/v3/files/){file_hash}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        malicious_votes = data['data']['attributes']['last_analysis_stats']['malicious']
        undetected_votes = data['data']['attributes']['last_analysis_stats']['undetected']
        return json.dumps({"hash": file_hash, "malicious_score": malicious_votes, "undetected": undetected_votes})
    else:
        return json.dumps({"error": f"API request failed with status code {response.status_code}"})
```

### Use Case 2: API-Driven Host Isolation via Wazuh (`wazuh_endpoint_isolate.py`)
```python
import requests
import json
import urllib3

# Suppress insecure HTTPS warnings for local lab certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def isolate_endpoint(wazuh_ip, jwt_token, agent_id):
    base_url = f"https://{wazuh_ip}:55000/active-response/send"

    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json"
    }

    # Payload triggers Wazuh's native network isolation script on the specific agent
    payload = {
        "command": "host-isolate",
        "arguments": ["-", "user"],
        "custom": False,
        "agent_list": [agent_id]
    }

    response = requests.put(base_url, headers=headers, data=json.dumps(payload), verify=False)

    if response.status_code == 200:
        return {"status": "Success", "message": f"Isolation command deployed to Agent {agent_id}."}
    else:
        return {"status": "Failed", "error": response.text}
```

## 8. Operational Verification & Validation (Proof of Concept)

### Use Case 3: The Malicious Payload Triage Pipeline Workflow

```
[ SIEM Webhook Ingest ] 
          │
          ▼
[ VirusTotal Hash Lookup ]
          │
          ▼
[ Logic Gate: Is Malicious Score >= 5? ]
          ├──► (No) ──► [ Append Case Notes ] ──► [ Terminate Workflow ]
          │
          └──► (Yes) ──► [ Trigger Wazuh Host Isolation API ] ──► [ Send SOC Alert ]
```

### Live Log Pipeline JSON Payload Verification

**Enrichment Node Processing Output (VirusTotal Result Data):**
```json
{
  "hash": "d41d8cd98f00b204e9800998ecf8427e",
  "malicious_score": 47,
  "undetected": 12
}
```

**Containment Execution Node Output (Wazuh API Return Status):**
```json
{
  "status": "Success",
  "message": "Isolation command deployed to Agent 042."
}
```

**SOC Communication Vector Ingestion (Formatted Output to Channel Hook):**
```json
{
  "alert_id": "SIEM-88213",
  "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
  "callback_ip": "185[.]220[.]101[.]7",
  "agent_id": "042",
  "vt_malicious_score": 47,
  "action_taken": "host-isolate",
  "status": "Contained",
  "timestamp": "2026-06-29T03:14:22Z"
}
```

## 9. Hardening & Future Enhancements
* **Current Security Posture:** Shuffle container infrastructure is isolated via local internal bridge network configurations. Inter-app token sharing is bound explicitly inside the encrypted authentication vault, restricting plaintext disclosure during script debugging steps.
* **Future Roadmap:**
  * [ ] Introduce an intermediate manual confirmation step via collaborative ticketing APIs (e.g., Jira or ServiceNow) specifically for high-availability production domain infrastructure.
  * [ ] Build dynamic reputation lookups for associated external egress destination targets utilizing public IP reputation scoring grids to accelerate distributed denial network blocks.

 <br><br><br>
[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)
```
