import pandas as pd

from ml.preprocessing import prepare_ml_data
from ml.feature_selection import select_features
from ml.anomaly_detection import AnomalyDetector
from ml.classifier import ThreatClassifier
from ml.scoring import score_event
from ml.rules import check_security_rules
from ml.explainability import generate_explanation


class PredictionService:
    """
    Service responsible for generating
    security predictions.
    """

    def __init__(
        self,
        anomaly_detector=None,
        classifier=None
    ):

        self.anomaly_detector = (
            anomaly_detector
        )

        self.classifier = classifier

    # --------------------------------------------------
    # Prepare data
    # --------------------------------------------------

    def prepare_data(self, df):

        if df is None or df.empty:
            raise ValueError(
                "Input dataframe is empty."
            )

        selected_features = select_features(
            df
        )

        processed_data, scaler = (
            prepare_ml_data(
                selected_features
            )
        )

        return (
            processed_data,
            scaler
        )

    # --------------------------------------------------
    # Detect anomalies
    # --------------------------------------------------

    def detect_anomalies(self, X):

        if self.anomaly_detector is None:

            detector = AnomalyDetector()

            detector.train(X)

            self.anomaly_detector = detector

        predictions = (
            self.anomaly_detector.predict(X)
        )

        scores = (
            self.anomaly_detector.anomaly_scores(X)
        )

        return predictions, scores

    # --------------------------------------------------
    # Classify threats
    # --------------------------------------------------

    def classify_threats(self, X):

        if self.classifier is None:

            return None, None

        if not self.classifier.is_trained:

            return None, None

        predictions = (
            self.classifier.predict(X)
        )

        confidence = (
            self.classifier.confidence_score(X)
        )

        return (
            predictions,
            confidence
        )

    # --------------------------------------------------
    # Generate predictions
    # --------------------------------------------------

    def predict(self, df):

        if df is None or df.empty:
            raise ValueError(
                "Input dataframe is empty."
            )

        original_data = df.copy()

        # ----------------------------------------------
        # Prepare ML data
        # ----------------------------------------------

        X, scaler = self.prepare_data(
            original_data
        )

        # ----------------------------------------------
        # Anomaly detection
        # ----------------------------------------------

        anomaly_predictions, anomaly_scores = (
            self.detect_anomalies(X)
        )

        # ----------------------------------------------
        # Threat classification
        # ----------------------------------------------

        classifier_predictions, classifier_confidence = (
            self.classify_threats(X)
        )

        results = original_data.copy()

        # ----------------------------------------------
        # Add anomaly information
        # ----------------------------------------------

        results[
            "anomaly_prediction"
        ] = anomaly_predictions

        results[
            "anomaly_score"
        ] = anomaly_scores

        results[
            "anomaly_status"
        ] = pd.Series(
            anomaly_predictions
        ).map(
            {
                1: "Normal",
                -1: "Suspicious"
            }
        ).values

        # ----------------------------------------------
        # Add classifier information
        # ----------------------------------------------

        if classifier_predictions is not None:

            results[
                "threat_prediction"
            ] = classifier_predictions

            results[
                "classifier_confidence"
            ] = classifier_confidence

        # ----------------------------------------------
        # Scoring
        # ----------------------------------------------

        scored_events = []

        for index, event in results.iterrows():

            score = score_event(
                event
            )

            rule_result = check_security_rules(
                event
            )

            explanation = generate_explanation(
                {
                    **event.to_dict(),
                    **score
                }
            )

            scored_event = {
                **event.to_dict(),

                "prediction": score[
                    "prediction"
                ],

                "confidence_score": score[
                    "confidence_score"
                ],

                "risk_level": score[
                    "risk_level"
                ],

                "rule_score": rule_result[
                    "rule_score"
                ],

                "rule_risk": rule_result[
                    "rule_risk"
                ],

                "triggered_rules": rule_result[
                    "triggered_rules"
                ],

                "explanation": explanation[
                    "reasons"
                ]
            }

            scored_events.append(
                scored_event
            )

        return pd.DataFrame(
            scored_events
        )


# ------------------------------------------------------
# Convenience function
# ------------------------------------------------------

def generate_predictions(df):

    service = PredictionService()

    return service.predict(
        df
    )