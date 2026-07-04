"""
Wazuh active response node.
Sends a host-isolate command to a Wazuh agent via the manager's REST API.

Requires: requests
Environment variables: WAZUH_MANAGER_IP, WAZUH_JWT_TOKEN
"""
import os
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


if __name__ == "__main__":
    wazuh_ip = os.getenv("WAZUH_MANAGER_IP", "10.10.0.10")
    jwt_token = os.getenv("WAZUH_JWT_TOKEN")
    result = isolate_endpoint(wazuh_ip, jwt_token, agent_id="01")
    print(json.dumps(result))
