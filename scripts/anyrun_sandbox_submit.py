"""
ANY.RUN Interactive Sandbox enrichment node.
Submits a URL flagged by the VirusTotal enrichment step for automated detonation
and pulls a verdict once analysis completes.

Requires: anyrun-sdk (pip install anyrun-sdk)
Environment variable: ANY_RUN_SANDBOX_API_KEY

Reference: https://github.com/anyrun/anyrun-sdk
"""
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


if __name__ == "__main__":
    api_key = os.getenv("ANY_RUN_SANDBOX_API_KEY")
    # Example staging URL flagged by the VirusTotal enrichment step
    flagged_url = "hxxp://203.0.113.10/update.ps1"
    result = detonate_url(flagged_url.replace("hxxp", "http"), api_key)
    print(result)

# Note: method names above (run_url_analysis, get_task_status, get_analysis_verdict,
# get_analysis_report) reflect the anyrun-sdk public interface as documented at the
# link above. Confirm against the installed SDK version before running in production.
