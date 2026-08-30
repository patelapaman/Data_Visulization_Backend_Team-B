
"""
Prediction Model

Represents the result produced by the machine-learning
threat detection system.
"""


class Prediction:

    ALLOWED_PREDICTIONS = [
        "Normal",
        "Benign",
        "Suspicious",
        "Malicious",
        "Anomaly",
        "Unknown"
    ]

    def __init__(
        self,
        prediction_id=None,
        event_id=None,
        prediction="Unknown",
        confidence=0,
        model_name=None,
        model_version=None,
        anomaly_score=None,
        risk_score=None,
        risk_level=None,
        features=None,
        explanation=None,
        created_at=None
    ):

        self.prediction_id = prediction_id

        self.event_id = event_id

        self.prediction = prediction

        self.confidence = confidence

        self.model_name = model_name

        self.model_version = model_version

        self.anomaly_score = anomaly_score

        self.risk_score = risk_score

        self.risk_level = risk_level

        self.features = (
            features if features is not None else {}
        )

        self.explanation = (
            explanation if explanation is not None else {}
        )

        self.created_at = created_at

    # ---------------------------------------------------------
    # Validation
    # ---------------------------------------------------------

    def validate(self):
        """
        Validate prediction data.
        """

        errors = []

        # Validate prediction label
        if self.prediction not in self.ALLOWED_PREDICTIONS:

            errors.append(
                f"Invalid prediction: {self.prediction}"
            )

        # Validate confidence
        try:

            confidence = float(
                self.confidence
            )

            if confidence < 0 or confidence > 100:

                errors.append(
                    "confidence must be between 0 and 100"
                )

        except (TypeError, ValueError):

            errors.append(
                "confidence must be numeric"
            )

        # Validate risk score
        if self.risk_score is not None:

            try:

                risk_score = float(
                    self.risk_score
                )

                if risk_score < 0 or risk_score > 100:

                    errors.append(
                        "risk_score must be between 0 and 100"
                    )

            except (TypeError, ValueError):

                errors.append(
                    "risk_score must be numeric"
                )

        return errors

    # ---------------------------------------------------------
    # Convert to Dictionary
    # ---------------------------------------------------------

    def to_dict(self):
        """
        Convert Prediction object to dictionary.
        """

        return {
            "prediction_id":
                self.prediction_id,

            "event_id":
                self.event_id,

            "prediction":
                self.prediction,

            "confidence":
                self.confidence,

            "model_name":
                self.model_name,

            "model_version":
                self.model_version,

            "anomaly_score":
                self.anomaly_score,

            "risk_score":
                self.risk_score,

            "risk_level":
                self.risk_level,

            "features":
                self.features,

            "explanation":
                self.explanation,

            "created_at":
                self.created_at
        }

    # ---------------------------------------------------------
    # Create From Dictionary
    # ---------------------------------------------------------

    @classmethod
    def from_dict(cls, data):
        """
        Create Prediction object from dictionary.
        """

        if not data:
            return None

        return cls(
            prediction_id=data.get(
                "prediction_id"
            ),

            event_id=data.get(
                "event_id"
            ),

            prediction=data.get(
                "prediction",
                "Unknown"
            ),

            confidence=data.get(
                "confidence",
                0
            ),

            model_name=data.get(
                "model_name"
            ),

            model_version=data.get(
                "model_version"
            ),

            anomaly_score=data.get(
                "anomaly_score"
            ),

            risk_score=data.get(
                "risk_score"
            ),

            risk_level=data.get(
                "risk_level"
            ),

            features=data.get(
                "features",
                {}
            ),

            explanation=data.get(
                "explanation",
                {}
            ),

            created_at=data.get(
                "created_at"
            )
        )

    # ---------------------------------------------------------
    # ML Result Helper
    # ---------------------------------------------------------

    def set_prediction(
        self,
        prediction,
        confidence
    ):
        """
        Set ML prediction and confidence.
        """

        self.prediction = prediction
        self.confidence = confidence

    def set_risk(
        self,
        risk_score,
        risk_level
    ):
        """
        Set calculated risk information.
        """

        self.risk_score = risk_score
        self.risk_level = risk_level

    # ---------------------------------------------------------
    # Representation
    # ---------------------------------------------------------

    def __repr__(self):

        return (
            f"Prediction("
            f"event_id={self.event_id}, "
            f"prediction={self.prediction}, "
            f"confidence={self.confidence}, "
            f"risk_score={self.risk_score})"
        )

