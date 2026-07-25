"""
Wazuh active response node.
Blocks a malicious IP on a specific agent through the Wazuh manager REST API.

Requires: requests
Environment variables: WAZUH_MANAGER_IP, WAZUH_API_USER, WAZUH_API_PASSWORD

API notes (verified against Wazuh API reference):
  - The endpoint is PUT /active-response, not /active-response/send.
  - Target agents are passed as the agents_list query parameter, not in the body.
  - firewall-drop is a built-in Wazuh active response script. The "!" prefix
    tells the manager to invoke the script directly by name.
  - Scripts that act on an indicator read it from the alert object in the body.

Note on full host isolation: Wazuh ships no built-in host-isolate command. The
built-in scripts are firewall-drop, host-deny, route-null, win_route-null,
disable-account, and restart-wazuh. Full network isolation requires a custom
active response script placed in /var/ossec/active-response/bin/, registered as
a <command> block in ossec.conf, and invoked with custom=true. See
config/ossec-active-response.conf for that registration block.
"""
import os
import json
import requests
import urllib3

# Suppress insecure HTTPS warnings for local lab certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_token(wazuh_ip, username, password):
    """Exchange basic auth credentials for a short-lived JWT."""
    url = f"https://{wazuh_ip}:55000/security/user/authenticate"
    response = requests.post(url, auth=(username, password), verify=False, timeout=20)
    response.raise_for_status()
    return response.json()["data"]["token"]


def block_ip(wazuh_ip, jwt_token, agent_id, malicious_ip):
    """Run the built-in firewall-drop script on one agent against one IP."""
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

    response = requests.put(
        url,
        headers=headers,
        params=params,
        data=json.dumps(payload),
        verify=False,
        timeout=20
    )

    if response.status_code == 200:
        return {
            "status": "Success",
            "message": f"firewall-drop sent to agent {agent_id} for {malicious_ip}."
        }
    return {"status": "Failed", "error": response.text}


if __name__ == "__main__":
    manager_ip = os.getenv("WAZUH_MANAGER_IP", "10.10.0.10")
    api_user = os.getenv("WAZUH_API_USER")
    api_password = os.getenv("WAZUH_API_PASSWORD")

    token = get_token(manager_ip, api_user, api_password)
    # Example callback IP from the enrichment step (RFC 5737 documentation range)
    result = block_ip(manager_ip, token, agent_id="001", malicious_ip="198.51.100.7")
    print(json.dumps(result))
