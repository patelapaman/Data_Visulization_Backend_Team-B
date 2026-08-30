class Incident:
    def __init__(
        self,
        incident_id,
        asset_id,
        event_id,
        incident_type,
        severity,
        detected_time,
        resolved_time,
        status,

        # Milestone 3 fields
        risk_score=0,
        risk_level="Low",
        priority="Low",
        ml_confidence=0,
        mitre_technique=None,
        ioc_status=None,
        recommendations=None,
        related_events=None,
        attack_chain=None,
        reasons=None
    ):
        # Existing fields
        self.incident_id = incident_id
        self.asset_id = asset_id
        self.event_id = event_id
        self.incident_type = incident_type
        self.severity = severity
        self.detected_time = detected_time
        self.resolved_time = resolved_time
        self.status = status

        # Milestone 3 fields
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.priority = priority
        self.ml_confidence = ml_confidence
        self.mitre_technique = mitre_technique
        self.ioc_status = ioc_status
        self.recommendations = (
            recommendations if recommendations is not None else []
        )
        self.related_events = (
            related_events if related_events is not None else []
        )
        self.attack_chain = (
            attack_chain if attack_chain is not None else []
        )
        self.reasons = (
            reasons if reasons is not None else []
        )

    def to_dict(self):
        """
        Convert incident object into a dictionary.
        """

        return {
            # Existing fields
            "incident_id": self.incident_id,
            "asset_id": self.asset_id,
            "event_id": self.event_id,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "detected_time": self.detected_time,
            "resolved_time": self.resolved_time,
            "status": self.status,

            # Milestone 3 fields
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "priority": self.priority,
            "ml_confidence": self.ml_confidence,
            "mitre_technique": self.mitre_technique,
            "ioc_status": self.ioc_status,
            "recommendations": self.recommendations,
            "related_events": self.related_events,
            "attack_chain": self.attack_chain,
            "reasons": self.reasons
        }

    @classmethod
    def from_dict(cls, data):
        """
        Create an Incident object from a dictionary.
        """

        return cls(
            incident_id=data.get("incident_id"),
            asset_id=data.get("asset_id"),
            event_id=data.get("event_id"),
            incident_type=data.get("incident_type"),
            severity=data.get("severity"),
            detected_time=data.get("detected_time"),
            resolved_time=data.get("resolved_time"),
            status=data.get("status", "Open"),

            # Milestone 3 fields
            risk_score=data.get("risk_score", 0),
            risk_level=data.get("risk_level", "Low"),
            priority=data.get("priority", "Low"),
            ml_confidence=data.get("ml_confidence", 0),
            mitre_technique=data.get(
                "mitre_technique"
            ),
            ioc_status=data.get(
                "ioc_status"
            ),
            recommendations=data.get(
                "recommendations", []
            ),
            related_events=data.get(
                "related_events", []
            ),
            attack_chain=data.get(
                "attack_chain", []
            ),
            reasons=data.get(
                "reasons", []
            )
        )

    def validate(self):
        """
        Validate incident data.
        """

        errors = []

        # Validate risk score
        try:
            score = float(self.risk_score)

            if score < 0 or score > 100:
                errors.append(
                    "risk_score must be between 0 and 100"
                )

        except (TypeError, ValueError):
            errors.append(
                "risk_score must be a number"
            )

        # Validate status
        allowed_statuses = [
            "Open",
            "Investigating",
            "Resolved",
            "False Positive"
        ]

        if self.status not in allowed_statuses:
            errors.append(
                f"Invalid status: {self.status}"
            )

        # Validate priority
        allowed_priorities = [
            "Immediate",
            "High",
            "Medium",
            "Low"
        ]

        if self.priority not in allowed_priorities:
            errors.append(
                f"Invalid priority: {self.priority}"
            )

        return errors

    def __repr__(self):
        return (
            f"Incident("
            f"incident_id={self.incident_id}, "
            f"risk_score={self.risk_score}, "
            f"risk_level={self.risk_level}, "
            f"priority={self.priority}, "
            f"status={self.status})"
        )
