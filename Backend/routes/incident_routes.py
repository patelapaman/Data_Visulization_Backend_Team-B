from flask import Blueprint, request, jsonify
from datetime import datetime

from risk.risk_score import calculate_risk_assessment
from risk.prioritization import prioritize_incident
from risk.recommendations import generate_recommendations
from risk.correlation import correlate_events, create_attack_chain


incident_bp = Blueprint(
    "incidents",
    __name__,
    url_prefix="/api/incidents"
)


# Temporary in-memory storage.
# Replace this with MongoDB repository functions
# when connecting the incident API to the database.
incidents = []


def generate_incident_id():
    """
    Generate a simple incident ID.
    """

    return f"INC-{1000 + len(incidents) + 1}"


@incident_bp.route("", methods=["POST"])
def create_incident():
    """
    Create an incident from a security event.

    Expected JSON:
    {
        "event_id": "EVT-1001",
        "event_type": "Brute Force",
        "timestamp": "2026-08-29T10:00:00",
        "user_id": "USER-01",
        "asset_id": "DB-001",
        "severity": "Critical",
        "ml_prediction": "Suspicious",
        "ml_confidence": 92,
        "anomaly_score": -0.74,
        "cvss_score": 9.2,
        "asset_criticality": "Critical",
        "ioc_status": "Malicious",
        "mitre_technique": "T1110",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20"
    }
    """

    try:
        event = request.get_json()

        if not event:
            return jsonify({
                "success": False,
                "error": "Event data is required"
            }), 400

        # Risk assessment
        risk = calculate_risk_assessment(event)

        event.update(risk)

        # Priority
        priority = prioritize_incident(
            risk["risk_score"]
        )

        # Recommendations
        recommendations = generate_recommendations(
            event
        )

        incident = {
            "incident_id": generate_incident_id(),
            "event_id": event.get("event_id"),
            "threat_type": event.get("event_type"),
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "priority": priority["priority"],
            "affected_asset": event.get("asset_id"),
            "ml_confidence": event.get(
                "ml_confidence"
            ),
            "mitre_techniques": [
                event.get("mitre_technique")
            ] if event.get("mitre_technique") else [],
            "ioc_status": event.get(
                "ioc_status"
            ),
            "related_events": [],
            "attack_chain": [],
            "reasons": [],
            "recommendations": recommendations,
            "status": "Open",
            "created_at": datetime.utcnow().isoformat()
        }

        incidents.append(incident)

        return jsonify({
            "success": True,
            "message": "Incident created successfully",
            "incident": incident
        }), 201

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@incident_bp.route("", methods=["GET"])
def get_incidents():
    """
    Return all incidents.
    """

    return jsonify({
        "success": True,
        "count": len(incidents),
        "incidents": incidents
    }), 200


@incident_bp.route("/<incident_id>", methods=["GET"])
def get_incident(incident_id):
    """
    Get a specific incident.
    """

    for incident in incidents:

        if incident["incident_id"] == incident_id:

            return jsonify({
                "success": True,
                "incident": incident
            }), 200

    return jsonify({
        "success": False,
        "error": "Incident not found"
    }), 404


@incident_bp.route("/<incident_id>/status", methods=["PUT"])
def update_incident_status(incident_id):
    """
    Update incident status.

    Allowed statuses:
    Open
    Investigating
    Resolved
    False Positive
    """

    data = request.get_json()

    if not data or "status" not in data:

        return jsonify({
            "success": False,
            "error": "Status is required"
        }), 400

    allowed_statuses = [
        "Open",
        "Investigating",
        "Resolved",
        "False Positive"
    ]

    status = data["status"]

    if status not in allowed_statuses:

        return jsonify({
            "success": False,
            "error": "Invalid incident status",
            "allowed_statuses": allowed_statuses
        }), 400

    for incident in incidents:

        if incident["incident_id"] == incident_id:

            incident["status"] = status

            return jsonify({
                "success": True,
                "message": "Incident status updated",
                "incident": incident
            }), 200

    return jsonify({
        "success": False,
        "error": "Incident not found"
    }), 404


@incident_bp.route("/correlate", methods=["POST"])
def correlate_incident_events():
    """
    Correlate multiple security events.

    Expected JSON:
    {
        "events": [
            {...},
            {...}
        ]
    }
    """

    try:
        data = request.get_json()

        if not data or "events" not in data:

            return jsonify({
                "success": False,
                "error": "events are required"
            }), 400

        events = data["events"]

        if not isinstance(events, list):

            return jsonify({
                "success": False,
                "error": "events must be a list"
            }), 400

        groups = correlate_events(events)

        attack_chains = []

        for group in groups:

            attack_chain = create_attack_chain(
                group
            )

            attack_chains.append({
                "event_count": len(group),
                "events": group,
                "attack_chain": attack_chain
            })

        return jsonify({
            "success": True,
            "groups": attack_chains
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500