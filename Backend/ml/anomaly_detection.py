import pandas as pd
import numpy as np

from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """
    Isolation Forest based anomaly detector.
    """

    def __init__(
        self,
        contamination=0.05,
        random_state=42
    ):

        self.contamination = contamination
        self.random_state = random_state

        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )

        self.is_trained = False

    # --------------------------------------------------
    # Train model
    # --------------------------------------------------

    def train(self, X):
        """
        Train Isolation Forest.
        """

        if X is None or len(X) == 0:
            raise ValueError(
                "Training data is empty."
            )

        self.model.fit(X)

        self.is_trained = True

        print(
            "Isolation Forest model trained successfully."
        )

        return self

    # --------------------------------------------------
    # Predict anomalies
    # --------------------------------------------------

    def predict(self, X):
        """
        Predict whether events are normal or anomalous.

        Returns:
            1  = Normal
            -1 = Anomaly
        """

        if not self.is_trained:
            raise RuntimeError(
                "Model has not been trained."
            )

        return self.model.predict(X)

    # --------------------------------------------------
    # Calculate anomaly scores
    # --------------------------------------------------

    def anomaly_scores(self, X):
        """
        Generate anomaly scores.

        Higher values generally indicate
        more normal observations.
        """

        if not self.is_trained:
            raise RuntimeError(
                "Model has not been trained."
            )

        return self.model.decision_function(X)

    # --------------------------------------------------
    # Add predictions to dataframe
    # --------------------------------------------------

    def detect(self, df, X):
        """
        Add anomaly predictions and scores
        to the original dataframe.
        """

        if df is None or df.empty:
            raise ValueError(
                "Input dataframe is empty."
            )

        predictions = self.predict(X)
        scores = self.anomaly_scores(X)

        result = df.copy()

        # --------------------------------------------------
        # Convert Isolation Forest output
        # --------------------------------------------------

        result["anomaly_prediction"] = predictions

        result["anomaly_status"] = np.where(
            predictions == -1,
            "Suspicious",
            "Normal"
        )

        result["anomaly_score"] = scores

        return result


def detect_anomalies(
    df,
    contamination=0.05
):
    """
    Convenience function for anomaly detection.

    Parameters
    ----------
    df : pandas.DataFrame
        ML-ready dataframe.

    Returns
    -------
    pandas.DataFrame
        Dataframe containing anomaly results.
    """

    if df is None or df.empty:
        raise ValueError(
            "Input dataframe is empty."
        )

    detector = AnomalyDetector(
        contamination=contamination
    )

    detector.train(df)

    predictions = detector.predict(df)

    scores = detector.anomaly_scores(df)

    result = df.copy()

    result["anomaly_prediction"] = predictions

    result["anomaly_status"] = predictions.map(
        {
            1: "Normal",
            -1: "Suspicious"
        }
    )

    result["anomaly_score"] = scores

    return result