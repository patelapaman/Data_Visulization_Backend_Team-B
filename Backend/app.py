from flask import Flask, jsonify
from flask_cors import CORS

# ---------------------------------------------------------
# Database
# ---------------------------------------------------------

from database.mongodb import get_database


# ---------------------------------------------------------
# Routes
# ---------------------------------------------------------

from routes.assets import assets_bp
from routes.vulnerabilities import vulnerabilities_bp
from routes.threats import threats_bp
from routes.incidents import incidents_bp
from routes.analytics import analytics_bp
from routes.dashboard import dashboard_bp

# ML / Prediction routes
from routes.prediction_routes import prediction_bp
from routes.anomaly_routes import anomaly_bp

# Export route
from routes.export import export_bp


# =========================================================
# Flask Application
# =========================================================

app = Flask(__name__)

# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

CORS(app)


# ---------------------------------------------------------
# Application Configuration
# ---------------------------------------------------------

app.config["JSON_SORT_KEYS"] = False


# =========================================================
# Register Blueprints
# =========================================================

app.register_blueprint(
    assets_bp
)

app.register_blueprint(
    vulnerabilities_bp
)

app.register_blueprint(
    threats_bp
)

app.register_blueprint(
    incidents_bp
)

app.register_blueprint(
    analytics_bp
)

app.register_blueprint(
    dashboard_bp
)

app.register_blueprint(
    prediction_bp
)

app.register_blueprint(
    anomaly_bp
)

app.register_blueprint(
    export_bp
)


# =========================================================
# Home / API Information
# =========================================================

@app.route(
    "/",
    methods=["GET"]
)
def home():

    return jsonify({
        "success": True,
        "message": "AI-Assisted Threat Detection Backend",
        "status": "running",
        "version": "1.0.0"
    })


# =========================================================
# Health Check
# =========================================================

@app.route(
    "/health",
    methods=["GET"]
)
def health():

    try:

        db = get_database()

        # Test MongoDB connection
        db.command(
            "ping"
        )

        mongodb_status = "connected"

    except Exception as error:

        mongodb_status = (
            f"disconnected: {str(error)}"
        )

    return jsonify({

        "success": True,

        "application": "AI-Assisted Threat Detection Dashboard",

        "backend": "running",

        "mongodb": mongodb_status

    })


# =========================================================
# API Health Check
# =========================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def api_health():

    return jsonify({

        "success": True,

        "message": "API is working",

        "services": {

            "api": "running",

            "prediction": "available",

            "anomaly_detection": "available",

            "analytics": "available",

            "mongodb": "configured"

        }

    })


# =========================================================
# Error Handlers
# =========================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({

        "success": False,

        "error": "Endpoint not found",

        "message": "The requested API endpoint does not exist."

    }), 404


@app.errorhandler(500)
def internal_server_error(error):

    return jsonify({

        "success": False,

        "error": "Internal server error",

        "message": "An unexpected server error occurred."

    }), 500


# =========================================================
# Run Application
# =========================================================

if __name__ == "__main__":

    print("\n" + "=" * 60)

    print(
        "AI-ASSISTED THREAT DETECTION BACKEND"
    )

    print("=" * 60)

    print(
        "Server: http://127.0.0.1:5000"
    )

    print(
        "Health: http://127.0.0.1:5000/health"
    )

    print(
        "API Health: http://127.0.0.1:5000/api/health"
    )

    print("=" * 60 + "\n")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )