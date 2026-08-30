<<<<<<< HEAD
from flask import Blueprint, jsonify

from services.analytics_service import get_dashboard_analytics
=======

"""
Analytics Routes

Dashboard analytics APIs.
"""

from flask import Blueprint, jsonify, request

from services.analytics_service import AnalyticsService
>>>>>>> fef0746 (Milestone 3)

analytics_bp = Blueprint("analytics", __name__)


@analytics_bp.route("/", methods=["GET"])
def analytics():

<<<<<<< HEAD
    analytics_data = get_dashboard_analytics()

    return jsonify({
        "status": "success",
        "data": analytics_data
    })
=======
analytics_service = AnalyticsService()


# ---------------------------------------------------------
# Dashboard Summary
# ---------------------------------------------------------

@analytics_bp.route(
    "/summary",
    methods=["GET"]
)
def dashboard_summary():

    try:

        data = (
            analytics_service
            .get_dashboard_summary()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# Complete Dashboard Analytics
# ---------------------------------------------------------

@analytics_bp.route(
    "/dashboard",
    methods=["GET"]
)
def dashboard_analytics():

    try:

        data = (
            analytics_service
            .get_dashboard_analytics()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# Risk Distribution
# ---------------------------------------------------------

@analytics_bp.route(
    "/risk",
    methods=["GET"]
)
def risk_distribution():

    try:

        data = (
            analytics_service
            .get_risk_distribution()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# Incident Status
# ---------------------------------------------------------

@analytics_bp.route(
    "/incidents/status",
    methods=["GET"]
)
def incident_status():

    try:

        data = (
            analytics_service
            .get_incident_status_distribution()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# Threat Timeline
# ---------------------------------------------------------

@analytics_bp.route(
    "/timeline",
    methods=["GET"]
)
def threat_timeline():

    try:

        days = request.args.get(
            "days",
            default=7,
            type=int
        )

        if days <= 0:
            days = 7

        data = (
            analytics_service
            .get_threat_timeline(days)
        )

        return jsonify({
            "success": True,
            "days": days,
            "data": data
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# Attack Heatmap
# ---------------------------------------------------------

@analytics_bp.route(
    "/heatmap",
    methods=["GET"]
)
def attack_heatmap():

    try:

        data = (
            analytics_service
            .get_attack_heatmap()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# Top Targeted Assets
# ---------------------------------------------------------

@analytics_bp.route(
    "/top-assets",
    methods=["GET"]
)
def top_targeted_assets():

    try:

        limit = request.args.get(
            "limit",
            default=10,
            type=int
        )

        if limit <= 0:
            limit = 10

        data = (
            analytics_service
            .get_top_targeted_assets(limit)
        )

        return jsonify({
            "success": True,
            "limit": limit,
            "data": data
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# Threat Types
# ---------------------------------------------------------

@analytics_bp.route(
    "/threat-types",
    methods=["GET"]
)
def threat_types():

    try:

        data = (
            analytics_service
            .get_threat_type_distribution()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# ML Predictions
# ---------------------------------------------------------

@analytics_bp.route(
    "/predictions",
    methods=["GET"]
)
def prediction_statistics():

    try:

        data = (
            analytics_service
            .get_prediction_statistics()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# MITRE Distribution
# ---------------------------------------------------------

@analytics_bp.route(
    "/mitre",
    methods=["GET"]
)
def mitre_distribution():

    try:

        data = (
            analytics_service
            .get_mitre_distribution()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

>>>>>>> fef0746 (Milestone 3)
