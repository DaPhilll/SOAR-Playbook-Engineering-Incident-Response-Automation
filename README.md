# SOAR Playbook Engineering & Incident Response Automation

## Objective

This repository contains a suite of automated incident response playbooks engineered using Python and programmatic workflow logic. Built upon **Shuffle**, an open-source Security Orchestration, Automation, and Response (SOAR) platform, the project demonstrates the ability to architect end-to-end automated triage pipelines. By integrating third-party threat intelligence APIs (VirusTotal, AnyRun) and executing programmatic endpoint isolation scripts via the Wazuh REST API, these playbooks reduce Mean Time to Respond (MTTR), standardize investigative documentation, and accelerate threat containment.

### Engineering Capabilities Demonstrated

- **Open-Source SOAR Deployment:** Provisioning and configuring Shuffle via Docker Compose to serve as the centralized orchestration engine for security operations.
- **API Integration & Orchestration:** Engineering Python scripts and HTTP webhooks to interact with external threat intelligence platforms and internal security controls.
- **Automated Alert Enrichment:** Programmatically extracting Indicators of Compromise (IOCs) from raw SIEM alerts and enriching them with context from VirusTotal before analyst intervention.
- **Endpoint Containment Automation:** Developing programmatic workflow logic to trigger automated network isolation via the Wazuh Active Response API upon detection of confirmed high-severity threats.
- **Workflow Standardization:** Designing multi-stage triage orchestrations that enforce consistent, repeatable incident response procedures and reduce manual error during high-pressure events.

### Tools & Core Technologies

| Layer | Component / Technology Used | Purpose |
| :--- | :--- | :--- |
| **Orchestration Engine** | Shuffle (Open-Source SOAR) | Workflow logic design, webhook ingestion, and automation pipeline architecture |
| **Language** | Python 3.x (`requests`, `json`) | Core scripting language for API data parsing and logic flow |
| **Threat Intelligence** | VirusTotal API, AnyRun API | Reputation scoring, sandbox analysis, and IOC enrichment |
| **Containment Engine** | Wazuh REST API | Automated endpoint network isolation execution (Active Response) |
| **Data Structure** | JSON | Standardized format for parsing security events and API payloads |

---

## Repository Structure

```text
├── Shuffle-Workflows/
│   ├── Enrichment-Nodes/       # VirusTotal and AnyRun API scripts
│   ├── Containment-Nodes/      # Wazuh Active Response isolation scripts
│   └── Notification-Nodes/     # SOC channel alerting logic
└── Playbooks/
    └── Malicious-Payload-Triage.md   # Full orchestration workflow documentation
```

---

## Phase 1: SOAR Infrastructure Provisioning

To maintain an open-source, vendor-agnostic architecture, Shuffle was deployed locally to act as the automation broker between the SIEM and the threat intelligence platforms.

### Initializing the Shuffle Architecture

1. Launch a terminal session on an Ubuntu Server deployment node.
2. Clone the official Shuffle repository and initialize the containerized microservices (Frontend, Backend, Orborus, and OpenSearch) via Docker Compose:

    ```bash
    git clone https://github.com/Shuffle/Shuffle
    cd Shuffle
    sudo docker-compose up -d
    ```

3. Access the Shuffle administrative UI at `https://<Host_IP>:3443` and generate the required webhook URIs to begin ingesting external SIEM alerts.

---

## Phase 2: Automated Threat Intelligence Enrichment

The first stage of the automation pipeline handles the extraction and enrichment of IOCs immediately upon alert generation.

### Use Case 1: Programmatic VirusTotal Reputation Lookup

**Objective:** Automatically query the VirusTotal API for file hashes extracted from a JSON alert payload to determine a malicious confidence score.

**Python Node Logic (`virustotal_enrichment.py`):**

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

# Note: In Shuffle, environment variables (like API keys) are passed securely via the App authentication vault.
```

**Example Output:**

```json
{
  "hash": "d41d8cd98f00b204e9800998ecf8427e",
  "malicious_score": 47,
  "undetected": 12
}
```

---

## Phase 3: Automated Endpoint Containment

The containment phase gives the SOAR platform programmatic permissions to isolate compromised assets, removing the need for manual analyst login during time-sensitive events.

### Use Case 2: API-Driven Host Isolation via Wazuh

**Objective:** Execute a REST API PUT request to the Wazuh Manager to trigger an `active-response` script (e.g., `firewall-drop` or network quarantine) on the compromised endpoint.

**Python Node Logic (`wazuh_endpoint_isolate.py`):**

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

**Example Output:**

```json
{
  "status": "Success",
  "message": "Isolation command deployed to Agent 042."
}
```

---

## Phase 4: Multi-Stage Triage Orchestration

The final phase unites the modular scripts into a conditional incident response playbook within the Shuffle visual editor.

### Use Case 3: The Malicious Payload Triage Pipeline

**Objective:** Orchestrate a complete triage workflow for a reported malware execution alert.

**Workflow Logic Execution:**

1. **Ingest (Webhook):** Shuffle receives a POST request containing a raw JSON alert from the SIEM, including a suspicious file hash and the source Agent ID.
2. **Enrich (VirusTotal API):** The file hash is parsed and passed to the VirusTotal node.
3. **Analyze (Condition Gate):** A conditional logic gate evaluates the returned malicious score.
   - *If Score < 5:* Alert is classified as a false positive or low priority. The workflow updates the case notes and terminates.
   - *If Score >= 5:* The workflow proceeds to the containment branch.
4. **Contain (Wazuh API):** The Agent ID is passed to the Wazuh Active Response node, which drops network connections on the host to prevent lateral movement.
5. **Notify (Discord/Slack Webhook):** The SOAR compiles all findings (VT score, targeted agent, isolation confirmation) and sends a formatted message to the SOC communications channel.

**Example Output (SOC notification payload):**

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
