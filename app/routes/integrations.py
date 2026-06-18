from fastapi import APIRouter
import os

router = APIRouter()


@router.get("/crowdstrike/status")
def crowdstrike_status():
    client_id_configured = bool(os.getenv("FALCON_CLIENT_ID"))
    client_secret_configured = bool(os.getenv("FALCON_CLIENT_SECRET"))
    base_url = os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com")
    configured = client_id_configured and client_secret_configured

    return {
        "name": "CrowdStrike Falcon Integration",
        "status": "coming_soon",
        "configured": configured,
        "base_url": base_url if configured else "Not configured yet",
        "required_env_vars": [
            "FALCON_CLIENT_ID",
            "FALCON_CLIENT_SECRET",
            "FALCON_BASE_URL"
        ],
        "planned_capabilities": [
            {
                "title": "Falcon Identity Telemetry Import",
                "description": "Import Identity Protection detections such as password spraying, brute force, Kerberoasting, AS-REP roasting, DCSync, Pass-the-Hash, Golden Ticket usage, and AD-CS reconnaissance.",
                "value": "Connects Falcon Identity findings directly to ABSEGA validation and coverage gaps."
            },
            {
                "title": "Falcon Endpoint Detection Enrichment",
                "description": "Attach endpoint context to internal rules: hostname, username, command line, process tree, severity, and Falcon detection link.",
                "value": "Helps analysts compare ABSEGA Sigma logic with Falcon detections."
            },
            {
                "title": "Host Containment Workflow",
                "description": "Prepare response actions for managed endpoints such as contain host, lift containment, and create investigation ticket.",
                "value": "Turns validated detections into operational response workflows."
            },
            {
                "title": "User Risk Enrichment",
                "description": "Pull identity-risk context such as stale accounts, risky endpoints, privileged SID history, exposed passwords, and suspicious account attributes.",
                "value": "Improves prioritization and detection readiness scoring."
            },
            {
                "title": "Real Telemetry Ingestion",
                "description": "Save selected Falcon alerts as validation cases and use them inside the Test Runner.",
                "value": "Transforms real Falcon detections into reusable validation data."
            },
            {
                "title": "Coverage Gap Auto-Suggestions",
                "description": "Use Falcon blind spots and missed simulations to recommend new Sigma detections and telemetry requirements.",
                "value": "Closes gaps discovered during purple-team and identity attack simulations."
            }
        ],
        "planned_workflow": [
            "Fetch Falcon Identity or Endpoint alert",
            "Normalize Falcon fields into ABSEGA event format",
            "Map alert to MITRE ATT&CK technique",
            "Attach telemetry and affected assets",
            "Save event as validation case",
            "Run internal Sigma validation",
            "Calculate detection readiness score",
            "Suggest tuning or new detection",
            "Prepare response action such as contain host, disable user, block source IP, or notify IR"
        ],
        "security_notes": [
            "API secrets must stay in .env and must never be committed to GitHub.",
            "Response actions should require human approval first.",
            "Sensitive fields should be masked before AI analysis.",
            "All enrichment and response actions should be written to audit logs."
        ],
        "ui_badge": "COMING SOON",
        "priority": "high"
    }
