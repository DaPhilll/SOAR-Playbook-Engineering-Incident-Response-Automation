[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)

# SOAR Playbook Engineering & Incident Response Automation

## Repository Structure
```
/scripts
  virustotal_enrichment.py
  wazuh_endpoint_isolate.py
  anyrun_sandbox_submit.py
  deploy-shuffle.sh
/config
  ossec-active-response.conf
requirements.txt
LICENSE
README.md
```

## 1. Executive Summary & Objective
* **Problem Statement:** Manual threat intelligence lookups and console-switching during active incidents increase Mean Time to Respond (MTTR) and introduce error under time pressure.
* **Solution Overview:** This project builds a Security Orchestration, Automation, and Response (SOAR) workflow on the open-source Shuffle platform. It ingests SIEM alerts via webhook, enriches file hash indicators through the VirusTotal API, and blocks malicious callback IPs at the endpoint through the Wazuh API, automating the triage steps that would otherwise require manual work.
* **Core Capabilities:**
  * Endpoint containment via authenticated Wazuh active response API calls.
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
* **Command and Control:** Cutting off beacon connectivity by blocking the callback IP at the endpoint firewall.
* **Actions on Objectives:** Limiting data staging by blocking the outbound destination on the affected host.

## 5. MITRE ATT&CK Matrix Alignment

| Tactic | Technique ID | Technique Name | Mitigation Mechanism |
| :--- | :--- | :--- | :--- |
| **Execution** | T1204.002 | Malicious File | Endpoint alert ingestion with immediate hash reputation check via VirusTotal. |
| **Lateral Movement** | T1570 | Lateral Tool Transfer | Automated network boundary restriction to block asset-to-asset file replication. |
| **Mitigation** | M1037 | Filter Network Traffic | Authenticated API call to the Wazuh manager running `firewall-drop` on the affected agent. |

## 6. Threat Intelligence Tooling Integrated
* **VirusTotal v3 API:** Historical reputation scores, multi-engine detection tallies, and behavioral metadata for file indicators.
* **AnyRun Interactive Sandbox API:** Automated payload execution in an isolated sandbox to capture behavioral telemetry.

## 7. Implementation & Code

### Infrastructure Initialization
`scripts/deploy-shuffle.sh` — the OpenSearch prerequisites below are required; skipping them is the most common cause of the database container failing to start.
```bash
git clone https://github.com/Shuffle/Shuffle
cd Shuffle

# OpenSearch prerequisites
mkdir -p shuffle-database
sudo chown -R 1000:1000 shuffle-database
sudo swapoff -a

# Compose V2 syntax replaces the deprecated docker-compose
sudo docker compose up -d
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

### Use Case 2: Endpoint Containment via Wazuh API
`scripts/wazuh_endpoint_isolate.py`

Wazuh ships no built-in `host-isolate` command. The built-in active response scripts are `firewall-drop`, `host-deny`, `route-null`, `win_route-null`, `disable-account`, and `restart-wazuh`. This node uses `firewall-drop` to cut the endpoint's connection to the callback IP surfaced during enrichment. Full network isolation would require a custom script registered in `ossec.conf` and invoked with `custom: true` — see `config/ossec-active-response.conf`.

Two API details worth noting: the endpoint is `PUT /active-response` (not `/active-response/send`), and the target agents are passed as the `agents_list` query parameter rather than a body field.
```python
def block_ip(wazuh_ip, jwt_token, agent_id, malicious_ip):
    url = f"https://{wazuh_ip}:55000/active-response"

    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json"
    }

    # agents_list is a query parameter, not a body field.
    params = {"agents_list": agent_id}

    payload = {
        "command": "!firewall-drop",
        "alert": {
            "data": {
                "srcip": malicious_ip
            }
        }
    }

    response = requests.put(url, headers=headers, params=params,
                            data=json.dumps(payload), verify=False, timeout=20)

    if response.status_code == 200:
        return {"status": "Success",
                "message": f"firewall-drop sent to agent {agent_id} for {malicious_ip}."}
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
          └──► (Yes) ──► [ ANY.RUN Sandbox Detonation ] ──► [ Wazuh firewall-drop on Callback IP ] ──► [ Send SOC Alert ]
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
  "message": "firewall-drop sent to agent 001 for 198.51.100.7."
}
```

**SOC Notification Payload:**
```json
{
  "alert_id": "SIEM-LAB-001",
  "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
  "callback_ip": "198.51.100.7",
  "agent_id": "001",
  "vt_malicious_score": 47,
  "action_taken": "firewall-drop",
  "status": "Callback IP blocked"
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
