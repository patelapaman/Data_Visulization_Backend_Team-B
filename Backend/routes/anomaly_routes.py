from flask import Blueprint, request, jsonify

import pandas as pd

from ml.preprocessing import (
    prepare_ml_data
)

from ml.feature_selection import (
    select_features
)

from ml.anomaly_detection import (
    AnomalyDetector
)


anomaly_bp = Blueprint(
    "anomaly",
    __name__,
    url_prefix="/api/anomalies"
)


# ------------------------------------------------------
# POST /api/anomalies/detect
# ------------------------------------------------------

@anomaly_bp.route(
    "/detect",
    methods=["POST"]
)
def detect_anomalies():

    try:

        data = request.get_json()

        if not data:

            return jsonify({
                "success": False,
                "message": "No input data provided."
            }), 400

        # ------------------------------------------------
        # Accept event or events
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

        if dataframe.empty:

            return jsonify({
                "success": False,
                "message": "No events found."
            }), 400

        # ------------------------------------------------
        # Feature selection
        # ------------------------------------------------

        selected_features = select_features(
            dataframe
        )

        # ------------------------------------------------
        # ML preprocessing
        # ------------------------------------------------

        processed_data, scaler = (
            prepare_ml_data(
                selected_features
            )
        )

        # ------------------------------------------------
        # Train anomaly detector
        # ------------------------------------------------

        detector = AnomalyDetector()

        detector.train(
            processed_data
        )

        # ------------------------------------------------
        # Detect anomalies
        # ------------------------------------------------

        predictions = detector.predict(
            processed_data
        )

        scores = detector.anomaly_scores(
            processed_data
        )

        # ------------------------------------------------
        # Create result
        # ------------------------------------------------

        dataframe[
            "anomaly_prediction"
        ] = predictions

        dataframe[
            "anomaly_score"
        ] = scores

        dataframe[
            "anomaly_status"
        ] = pd.Series(
            predictions
        ).map(
            {
                1: "Normal",
                -1: "Suspicious"
            }
        ).values

        dataframe = dataframe.where(
            pd.notnull(dataframe),
            None
        )

        return jsonify({
            "success": True,
            "count": len(dataframe),
            "anomalies": dataframe.to_dict(
                orient="records"
            )
        }), 200

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


# ------------------------------------------------------
# GET /api/anomalies/health
# ------------------------------------------------------

@anomaly_bp.route(
    "/health",
    methods=["GET"]
)
def anomaly_health():

    return jsonify({
        "success": True,
        "service": "Anomaly Detection",
        "status": "running"
    }), 200