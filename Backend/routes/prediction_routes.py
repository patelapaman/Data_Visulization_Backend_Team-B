from flask import Blueprint, request, jsonify

import pandas as pd

from services.prediction_service import (
    PredictionService
)


prediction_bp = Blueprint(
    "prediction",
    __name__,
    url_prefix="/api"
)


# ------------------------------------------------------
# POST /api/predict
# ------------------------------------------------------

@prediction_bp.route(
    "/predict",
    methods=["POST"]
)
def predict():

    try:

        data = request.get_json()

        if not data:

            return jsonify({
                "success": False,
                "message": "No input data provided."
            }), 400

        # ------------------------------------------------
        # Accept either:
        #
        # {
        #     "event": {...}
        # }
        #
        # OR
        #
        # {
        #     "events": [{...}, {...}]
        # }
        # ------------------------------------------------

        if "event" in data:

            dataframe = pd.DataFrame(
                [data["event"]]
            )

        elif "events" in data:

            dataframe = pd.DataFrame(
                data["events"]
            )

        else:

            dataframe = pd.DataFrame(
                [data]
            )

        # ------------------------------------------------
        # Generate prediction
        # ------------------------------------------------

        service = PredictionService()

        result = service.predict(
            dataframe
        )

        # ------------------------------------------------
        # Convert to JSON
        # ------------------------------------------------

        result = result.where(
            pd.notnull(result),
            None
        )

        return jsonify({
            "success": True,
            "count": len(result),
            "predictions": result.to_dict(
                orient="records"
            )
        }), 200

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# ------------------------------------------------------
# GET /api/prediction/health
# ------------------------------------------------------

@prediction_bp.route(
    "/prediction/health",
    methods=["GET"]
)
def prediction_health():

    return jsonify({
        "success": True,
        "service": "Prediction Service",
        "status": "running"
    }), 200