"""
VirusTotal v3 API enrichment node.
Checks a file hash against VirusTotal's multi-engine detection database.

Requires: requests
Environment variable: VT_API_KEY
"""
import os
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


if __name__ == "__main__":
    api_key = os.getenv("VT_API_KEY")
    # Example: MD5 of an empty string, used here only as a placeholder value
    test_hash = "d41d8cd98f00b204e9800998ecf8427e"
    print(check_vt_reputation(test_hash, api_key))
