from datetime import datetime


class PredictionModel:
    """
    Model representing an ML prediction.
    """

    def __init__(
        self,
        event_id=None,
        prediction="Unknown",
        confidence_score=0,
        risk_level="Unknown",
        anomaly_status="Unknown",
        anomaly_score=0,
        threat_score=0,
        triggered_rules=None,
        explanation=None,
        model_version="v1",
        created_at=None
    ):

        self.event_id = event_id
        self.prediction = prediction
        self.confidence_score = confidence_score
        self.risk_level = risk_level
        self.anomaly_status = anomaly_status
        self.anomaly_score = anomaly_score
        self.threat_score = threat_score

        self.triggered_rules = (
            triggered_rules
            if triggered_rules is not None
            else []
        )

        self.explanation = (
            explanation
            if explanation is not None
            else []
        )

        self.model_version = model_version

        self.created_at = (
            created_at
            if created_at is not None
            else datetime.utcnow()
        )

    def to_dict(self):
        """
        Convert prediction object into
        a dictionary suitable for MongoDB.
        """

        return {
            "event_id": self.event_id,
            "prediction": self.prediction,
            "confidence_score": self.confidence_score,
            "risk_level": self.risk_level,
            "anomaly_status": self.anomaly_status,
            "anomaly_score": self.anomaly_score,
            "threat_score": self.threat_score,
            "triggered_rules": self.triggered_rules,
            "explanation": self.explanation,
            "model_version": self.model_version,
            "created_at": self.created_at
        }