from flask import Blueprint, request, jsonify

from risk.risk_score import calculate_risk_assessment
from risk.prioritization import prioritize_incident
from risk.recommendations import generate_recommendations


risk_bp = Blueprint(
    "risk",
    __name__,
    url_prefix="/api/risk"
)


@risk_bp.route("/calculate", methods=["POST"])
def calculate_risk():
    """
    Calculate risk score for a security event.

    Expected JSON:
    {
        "severity": "Critical",
        "ml_confidence": 92,
        "asset_criticality": "Critical",
        "cvss_score": 9.2,
        "ioc_status": "Malicious"
    }
    """

    try:
        event = request.get_json()

        if not event:
            return jsonify({
                "success": False,
                "error": "Request body is required"
            }), 400

        # Calculate risk
        risk = calculate_risk_assessment(event)

        # Calculate priority
        priority = prioritize_incident(
            risk["risk_score"]
        )

        # Add risk information to event
        event.update(risk)

        # Generate recommendations
        recommendations = generate_recommendations(
            event
        )

        return jsonify({
            "success": True,
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "priority": priority["priority"],
            "recommended_action": priority[
                "recommended_action"
            ],
            "recommendations": recommendations
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@risk_bp.route("/assess", methods=["POST"])
def assess_event():
    """
    Perform complete risk assessment.
    """

    try:
        event = request.get_json()

        if not event:
            return jsonify({
                "success": False,
                "error": "Event data is required"
            }), 400

        risk = calculate_risk_assessment(event)

        event.update(risk)

        priority = prioritize_incident(
            risk["risk_score"]
        )

        recommendations = generate_recommendations(
            event
        )

        return jsonify({
            "success": True,
            "assessment": {
                "risk_score": risk["risk_score"],
                "risk_level": risk["risk_level"],
                "priority": priority["priority"],
                "recommended_action": priority[
                    "recommended_action"
                ],
                "reasons": [],
                "recommendations": recommendations
            }
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500