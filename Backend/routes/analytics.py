from flask import Blueprint, jsonify, request

from services.analytics_service import (
    AnalyticsService
)


analytics_bp = Blueprint(
    "analytics",
    __name__,
    url_prefix="/api/analytics"
)


# =========================================================
# Dashboard Summary
# =========================================================

@analytics_bp.route(
    "/summary",
    methods=["GET"]
)
def dashboard_summary():

    try:

        data = (
            AnalyticsService
            .get_dashboard_summary()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# =========================================================
# Threat Summary
# =========================================================

@analytics_bp.route(
    "/threat-summary",
    methods=["GET"]
)
def threat_summary():

    try:

        data = (
            AnalyticsService
            .get_threat_summary()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# =========================================================
# Prediction Statistics
# =========================================================

@analytics_bp.route(
    "/prediction-statistics",
    methods=["GET"]
)
def prediction_statistics():

    try:

        data = (
            AnalyticsService
            .get_prediction_statistics()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# =========================================================
# Threat Timeline
# =========================================================

@analytics_bp.route(
    "/threat-timeline",
    methods=["GET"]
)
def threat_timeline():

    try:

        days = request.args.get(
            "days",
            7
        )

        data = (
            AnalyticsService
            .get_threat_timeline(days)
        )

        return jsonify({
            "success": True,
            "days": int(days),
            "data": data
        }), 200

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# =========================================================
# Attack Heatmap
# =========================================================

@analytics_bp.route(
    "/attack-heatmap",
    methods=["GET"]
)
def attack_heatmap():

    try:

        data = (
            AnalyticsService
            .get_attack_heatmap()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# =========================================================
# Top Targeted Assets
# =========================================================

@analytics_bp.route(
    "/top-targeted-assets",
    methods=["GET"]
)
def top_targeted_assets():

    try:

        limit = request.args.get(
            "limit",
            10
        )

        data = (
            AnalyticsService
            .get_top_targeted_assets(
                limit
            )
        )

        return jsonify({
            "success": True,
            "limit": int(limit),
            "data": data
        }), 200

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# =========================================================
# Model Performance
# =========================================================

@analytics_bp.route(
    "/model-performance",
    methods=["GET"]
)
def model_performance():

    try:

        data = (
            AnalyticsService
            .get_model_performance()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# =========================================================
# Recent Predictions
# =========================================================

@analytics_bp.route(
    "/recent-predictions",
    methods=["GET"]
)
def recent_predictions():

    try:

        limit = request.args.get(
            "limit",
            20
        )

        data = (
            AnalyticsService
            .get_recent_predictions(
                limit
            )
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# =========================================================
# Complete Dashboard
# =========================================================

@analytics_bp.route(
    "/dashboard",
    methods=["GET"]
)
def complete_dashboard():

    try:

        data = (
            AnalyticsService
            .get_complete_dashboard()
        )

        return jsonify({
            "success": True,
            "data": data
        }), 200

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500