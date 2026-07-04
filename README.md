[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)

# SOAR Playbook Engineering & Incident Response Automation

## Repository Structure
```
/scripts
  virustotal_enrichment.py
  wazuh_endpoint_isolate.py
  anyrun_sandbox_submit.py
  deploy-shuffle.sh
requirements.txt
LICENSE
README.md
```

## 1. Executive Summary & Objective
* **Problem Statement:** Manual threat intelligence lookups and console-switching during active incidents increase Mean Time to Respond (MTTR) and introduce error under time pressure.
* **Solution Overview:** This project builds a Security Orchestration, Automation, and Response (SOAR) workflow on the open-source Shuffle platform. It ingests SIEM alerts via webhook, enriches file hash indicators through the VirusTotal API, and isolates compromised endpoints through the Wazuh API, automating the triage steps that would otherwise require manual work.
* **Core Capabilities:**
  * Endpoint containment via authenticated API calls.
  * Automated enrichment of file hash indicators of compromise (IOCs).
  * Conditional logic to filter benign results before analyst routing.
  * Standardized notification output to a SOC communication channel.

## 2. Architecture & Environment Topology
This workflow runs in the shared lab environment (VMware Workstation Pro, `10.10.0.0/24`) and integrates directly with the Wazuh deployment on `SRV-SOC01`. Endpoint isolation actions target `WKSTN-01`.

* **Orchestration Host:** Ubuntu Server — `SRV-SOC01`, containerized.
* **Orchestration Core:** Shuffle SOAR engine (Frontend, Backend, Orborus execution engine, OpenSearch backend), deployed via Docker Compose.
* **Integration Plane:** HTTP webhooks for JSON payload ingestion from upstream SIEM alerting.
* **Integrated APIs:** VirusTotal v3 REST API, AnyRun Sandbox API, and the Wazuh manager API (`55000/tcp`).

## 3. Engineering Thought Process & Methodology
* **Design Considerations:** An open-source, vendor-agnostic SOAR platform avoids lock-in and lets integrations be built as plain Python scripts rather than proprietary plugins.
* **Technical Challenges & Resolution:**
  * **Challenge:** Raw SIEM JSON alerts have unpredictable structure, which can break parsing logic. Hardcoding API tokens inside script nodes is a security liability.
  * **Resolution:** Standardized JSON schema handling with exception handling across ingestion nodes. All credentials were moved out of script bodies into Shuffle's encrypted authentication vault.

## 4. Cyber Kill Chain & Threat Lifecycle Mapping
* **Installation & Exploitation:** Extracting suspicious artifacts from process telemetry immediately after execution.
* **Command and Control:** Cutting off persistent beacon connectivity via host isolation.
* **Actions on Objectives:** Limiting lateral movement and data staging through automated network quarantine.

## 5. MITRE ATT&CK Matrix Alignment

| Tactic | Technique ID | Technique Name | Mitigation Mechanism |
| :--- | :--- | :--- | :--- |
| **Execution** | T1204.002 | Malicious File | Endpoint alert ingestion with immediate hash reputation check via VirusTotal. |
| **Lateral Movement** | T1570 | Lateral Tool Transfer | Automated network boundary restriction to block asset-to-asset file replication. |
| **Mitigation** | M1040 | Endpoint Isolation | Authenticated API call to the Wazuh manager to apply an immediate host block. |

## 6. Threat Intelligence Tooling Integrated
* **VirusTotal v3 API:** Historical reputation scores, multi-engine detection tallies, and behavioral metadata for file indicators.
* **AnyRun Interactive Sandbox API:** Automated payload execution in an isolated sandbox to capture behavioral telemetry.

## 7. Implementation & Code

### Infrastructure Initialization
`scripts/deploy-shuffle.sh`
```bash
# Clone the Shuffle repository
git clone https://github.com/Shuffle/Shuffle
cd Shuffle

# Initialize the frontend, backend, database, and orchestration worker containers
sudo docker-compose up -d
```

### Use Case 1: VirusTotal Reputation Lookup
`scripts/virustotal_enrichment.py`
```python
import requests
import json

def check_vt_reputation(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
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

### Use Case 2: Host Isolation via Wazuh API
`scripts/wazuh_endpoint_isolate.py`
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

### Use Case 3: Sandbox Detonation via ANY.RUN SDK
`scripts/anyrun_sandbox_submit.py` — submits a flagged URL for automated detonation once the VirusTotal step crosses the malicious-score threshold, using the official `anyrun-sdk` package.
```python
import os
from anyrun.connectors import SandboxConnector

def detonate_url(target_url, api_key):
    with SandboxConnector.windows(api_key) as connector:
        analysis_id = connector.run_url_analysis(target_url)

        for status in connector.get_task_status(analysis_id):
            print(status)

        verdict = connector.get_analysis_verdict(analysis_id)

        if verdict in ("Suspicious", "Malicious"):
            connector.get_analysis_report(analysis_id, report_format="html", filepath="./reports")

        return {"analysis_id": analysis_id, "verdict": verdict}
```

## 8. Workflow Logic & Output Examples

### Malicious Payload Triage Pipeline
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
          └──► (Yes) ──► [ ANY.RUN Sandbox Detonation ] ──► [ Trigger Wazuh Host Isolation API ] ──► [ Send SOC Alert ]
```

The JSON below shows the data moving through each node. The file hash is the well-known MD5 of an empty string, used so it cannot be mistaken for a real indicator.

**Enrichment Node Output (VirusTotal Result):**
```json
{
  "hash": "d41d8cd98f00b204e9800998ecf8427e",
  "malicious_score": 47,
  "undetected": 12
}
```

**Containment Node Output (Wazuh API Return):**
```json
{
  "status": "Success",
  "message": "Isolation command deployed to Agent 01."
}
```

**SOC Notification Payload:**
```json
{
  "alert_id": "SIEM-LAB-001",
  "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
  "callback_ip": "198.51.100.7",
  "agent_id": "01",
  "vt_malicious_score": 47,
  "action_taken": "host-isolate",
  "status": "Contained"
}
```

## 9. Hardening & Future Enhancements
* **Current Posture:** Shuffle containers run on an isolated internal bridge network. Credential sharing between apps is scoped to the encrypted authentication vault to prevent plaintext exposure during script debugging.
* **Future Roadmap:**
  * [ ] Add a manual confirmation step via a ticketing API (GLPI) before containment on production-scope infrastructure.
  * [ ] Add IP reputation lookups for outbound connection targets to speed up network-level blocking.

## Dependencies
Install script dependencies with:
```bash
pip install -r requirements.txt
```
See `requirements.txt` for exact versions.

## License
MIT — see [LICENSE](./LICENSE).

<br><br><br>
[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)
