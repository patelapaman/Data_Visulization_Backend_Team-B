<<<<<<< HEAD
import os
from flask import Flask, jsonify
from flask_cors import CORS

from config import Config
from database.mongodb import connect_db

# Existing Blueprints
from routes.assets import assets_bp
from routes.vulnerabilities import vulnerabilities_bp
from routes.threats import threats_bp
from routes.incidents import incidents_bp
from routes.analytics import analytics_bp
from routes.dashboard import dashboard_bp
from routes.events import events_bp
from routes.database import database_bp

# New Blueprints
from routes.profile import profile_bp
from routes.notifications import notification_bp
from routes.preferences import preferences_bp
from routes.auth import auth_bp
from routes.milestone2 import milestone2_bp
from routes.section_analytics import section_analytics_bp
from milestone2_engine.runtime import runtime as milestone2_runtime

# Create outputs folder
OUTPUT_FOLDER = "outputs"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Enable CORS
    CORS(app)

    # Connect MongoDB
    connect_db(app)

    # Register Existing APIs
    app.register_blueprint(assets_bp, url_prefix="/api/assets")
    app.register_blueprint(vulnerabilities_bp, url_prefix="/api/vulnerabilities")
    app.register_blueprint(threats_bp, url_prefix="/api/threats")
    app.register_blueprint(incidents_bp, url_prefix="/api/incidents")
    app.register_blueprint(analytics_bp, url_prefix="/api/analytics")
    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")
    app.register_blueprint(events_bp, url_prefix="/api/events")
    app.register_blueprint(database_bp, url_prefix="/api/database")

    # Register New APIs
    app.register_blueprint(profile_bp, url_prefix="/api/profile")
    app.register_blueprint(notification_bp, url_prefix="/api/notifications")
    app.register_blueprint(preferences_bp, url_prefix="/api/preferences")
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(milestone2_bp, url_prefix="/api/milestone2")
    app.register_blueprint(section_analytics_bp, url_prefix="/api/section-analytics")

    # Initialize the Milestone 2 ML engine. If the local model cannot be loaded,
    # the API remains available and the /api/milestone2/health endpoint reports the error.
    try:
        milestone2_runtime.initialize()
        print("Milestone 2 ML engine initialized successfully")
    except Exception as exc:
        print(f"Milestone 2 ML engine initialization deferred: {exc}")

    @app.route("/")
    def home():
        return jsonify({
            "project": "AI-Assisted Threat Detection Dashboard",
            "version": "1.0.0",
            "status": "Running"
        })

    @app.route("/health")
    def health():
        from database.mongodb import get_db, is_mongodb_connected
        db = get_db()
        database_status = "MongoDB Connected" if is_mongodb_connected() else "Local demo storage"
        return jsonify({
            "status": "Healthy",
            "database": database_status,
            "database_name": db.name if db is not None else None,
            "milestone2": "Ready" if milestone2_runtime.ready else "Unavailable"
        }), 200

    @app.route("/api/pipeline/run")
    def run_pipeline():
        return jsonify({
            "message": "Pipeline executed successfully."
        })

    # Print all registered routes
    print("\n========== REGISTERED ROUTES ==========")
    print(app.url_map)
    print("=======================================\n")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
=======

"""
AI-Assisted Threat Detection Dashboard
Backend Application

Main Flask application.

This file:
- Creates the Flask application
- Configures CORS
- Connects MongoDB
- Registers API routes
- Provides health and database status endpoints
"""

import os

from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

from database.mongodb import (
    connect_db,
    get_database
)

# ---------------------------------------------------------
# Load Environment Variables
# ---------------------------------------------------------

load_dotenv()


# ---------------------------------------------------------
# Create Flask Application
# ---------------------------------------------------------

app = Flask(__name__)

CORS(app)


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

app.config["JSON_SORT_KEYS"] = False


# ---------------------------------------------------------
# Register Routes
# ---------------------------------------------------------

# Existing routes
try:
    from routes.assets import assets_bp
    app.register_blueprint(assets_bp)
except ImportError as e:
    print(f"Warning: Assets route not loaded: {e}")


try:
    from routes.vulnerabilities import vulnerabilities_bp
    app.register_blueprint(vulnerabilities_bp)
except ImportError as e:
    print(
        f"Warning: Vulnerabilities route not loaded: {e}"
    )


try:
    from routes.threats import threats_bp
    app.register_blueprint(threats_bp)
except ImportError as e:
    print(f"Warning: Threats route not loaded: {e}")


try:
    from routes.incidents import incidents_bp
    app.register_blueprint(incidents_bp)
except ImportError as e:
    print(
        f"Warning: Existing incidents route not loaded: {e}"
    )


try:
    from routes.dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp)
except ImportError as e:
    print(
        f"Warning: Dashboard route not loaded: {e}"
    )


# ---------------------------------------------------------
# Analytics Routes
# ---------------------------------------------------------

try:
    from routes.analytics import analytics_bp

    app.register_blueprint(
        analytics_bp
    )

except ImportError as e:

    print(
        f"Warning: Analytics route not loaded: {e}"
    )


# ---------------------------------------------------------
# Export Route
# ---------------------------------------------------------

try:
    from routes.export import export_bp

    app.register_blueprint(
        export_bp
    )

except ImportError as e:

    print(
        f"Warning: Export route not loaded: {e}"
    )


# ---------------------------------------------------------
# Prediction Routes
# ---------------------------------------------------------

try:
    from routes.prediction_routes import prediction_bp

    app.register_blueprint(
        prediction_bp
    )

except ImportError as e:

    print(
        f"Warning: Prediction route not loaded: {e}"
    )


# ---------------------------------------------------------
# Anomaly Routes
# ---------------------------------------------------------

try:
    from routes.anomaly_routes import anomaly_bp

    app.register_blueprint(
        anomaly_bp
    )

except ImportError as e:

    print(
        f"Warning: Anomaly route not loaded: {e}"
    )


# ---------------------------------------------------------
# Milestone 3 Routes
# ---------------------------------------------------------

try:
    from routes.risk_routes import risk_bp

    app.register_blueprint(
        risk_bp
    )

except ImportError as e:

    print(
        f"Warning: Risk route not loaded: {e}"
    )


try:
    from routes.incident_routes import incident_bp

    app.register_blueprint(
        incident_bp
    )

except ImportError as e:

    print(
        f"Warning: Incident service route not loaded: {e}"
    )


try:
    from routes.intelligence_routes import intelligence_bp

    app.register_blueprint(
        intelligence_bp
    )

except ImportError as e:

    print(
        "Warning: Intelligence route "
        f"not loaded: {e}"
    )


# ---------------------------------------------------------
# Health Check
# ---------------------------------------------------------

@app.route(
    "/",
    methods=["GET"]
)
def home():

    return jsonify({
        "success": True,
        "application":
            "AI-Assisted Threat Detection Dashboard",
        "status": "running",
        "message":
            "Backend API is running successfully"
    })


# ---------------------------------------------------------
# API Health Check
# ---------------------------------------------------------

@app.route(
    "/api/health",
    methods=["GET"]
)
def health():

    return jsonify({
        "success": True,
        "status": "healthy",
        "service": "Threat Detection Backend"
    })


# ---------------------------------------------------------
# MongoDB Health Check
# ---------------------------------------------------------

@app.route(
    "/api/health/database",
    methods=["GET"]
)
def database_health():

    try:

        connected = connect_db()

        if connected:

            db = get_database()

            return jsonify({
                "success": True,
                "status": "connected",
                "database":
                    db.name
            }), 200

        return jsonify({
            "success": False,
            "status": "disconnected",
            "message":
                "MongoDB connection failed"
        }), 503

    except Exception as e:

        return jsonify({
            "success": False,
            "status": "error",
            "message": str(e)
        }), 500


# ---------------------------------------------------------
# API Information
# ---------------------------------------------------------

@app.route(
    "/api",
    methods=["GET"]
)
def api_information():

    return jsonify({
        "success": True,
        "application":
            "AI-Assisted Threat Detection Dashboard",

        "version":
            "3.0.0",

        "endpoints": {

            "health":
                "/api/health",

            "database_health":
                "/api/health/database",

            "analytics":
                "/api/analytics/dashboard",

            "risk":
                "/api/risk",

            "predictions":
                "/api/predictions",

            "anomalies":
                "/api/anomalies",

            "incidents":
                "/api/incidents",

            "threat_intelligence":
                "/api/intelligence"
        }
    })


# ---------------------------------------------------------
# Error Handlers
# ---------------------------------------------------------

@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "success": False,
        "error": "Endpoint not found"
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):

    return jsonify({
        "success": False,
        "error": "HTTP method not allowed"
    }), 405


@app.errorhandler(500)
def internal_server_error(error):

    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500


# ---------------------------------------------------------
# Application Startup
# ---------------------------------------------------------

if __name__ == "__main__":

    print(
        "\n========================================"
    )

    print(
        " AI-Assisted Threat Detection Dashboard"
    )

    print(
        " Backend API"
    )

    print(
        "========================================"
    )

    print(
        "Starting Flask server..."
    )

    print(
        "API: http://127.0.0.1:5000"
    )

    print(
        "Health: "
        "http://127.0.0.1:5000/api/health"
    )

    print(
        "========================================\n"
    )

    # Check database without preventing
    # Flask from starting if MongoDB is unavailable.
    try:

        if connect_db():

            print(
                "✓ MongoDB connection successful"
            )

        else:

            print(
                "⚠ MongoDB is not connected"
            )

            print(
                "  Check your .env configuration."
            )

    except Exception as e:

        print(
            "⚠ MongoDB check failed:"
        )

        print(e)

    # Start Flask
    app.run(
        host=os.getenv(
            "FLASK_HOST",
            "127.0.0.1"
        ),

        port=int(
            os.getenv(
                "FLASK_PORT",
                5000
            )
        ),

        debug=os.getenv(
            "FLASK_DEBUG",
            "True"
        ).lower() == "true"
    )

>>>>>>> fef0746 (Milestone 3)
