"""
Incident Service

Handles:
- Incident creation
- Incident retrieval
- Incident status updates
- Event correlation
- Attack-chain detection
"""

from datetime import datetime

from risk.correlation import (
    correlate_events,
    create_attack_chain
)

from services.risk_service import assess_risk


class IncidentService:

    def __init__(self, collection=None):
        """
        Initialize Incident Service.

        Parameters
        ----------
        collection : pymongo.collection.Collection, optional
            MongoDB incidents collection.
        """

        self.collection = collection

    def generate_incident_id(self):
        """
        Generate a unique incident ID.
        """

        if self.collection is not None:

            try:
                count = self.collection.count_documents({})

                return f"INC-{1000 + count + 1}"

            except Exception:
                pass

        # Fallback ID
        timestamp = datetime.utcnow().strftime(
            "%Y%m%d%H%M%S"
        )

        return f"INC-{timestamp}"

    def create_incident(self, event):
        """
        Create an incident from a security event.
        """

        if not event:
            raise ValueError(
                "Security event is required"
            )

        # Perform risk assessment
        assessment = assess_risk(event)

        incident_id = self.generate_incident_id()

        incident = {
            "incident_id": incident_id,

            "event_id": event.get(
                "event_id"
            ),

            "threat_type": event.get(
                "event_type"
            ),

            "risk_score": assessment[
                "risk_score"
            ],

            "risk_level": assessment[
                "risk_level"
            ],

            "priority": assessment[
                "priority"
            ],

            "recommended_action": assessment[
                "recommended_action"
            ],

            "recommendations": assessment[
                "recommendations"
            ],

            "affected_asset": event.get(
                "asset_id"
            ),

            "source_ip": event.get(
                "source_ip"
            ),

            "destination_ip": event.get(
                "destination_ip"
            ),

            "user_id": event.get(
                "user_id"
            ),

            "mitre_technique": event.get(
                "mitre_technique"
            ),

            "ioc_status": event.get(
                "ioc_status"
            ),

            "ml_confidence": event.get(
                "ml_confidence"
            ),

            "status": "Open",

            "created_at": datetime.utcnow()
        }

        # Store in MongoDB
        if self.collection is not None:

            result = self.collection.insert_one(
                incident
            )

            incident["_id"] = str(
                result.inserted_id
            )

        return incident

    def get_all_incidents(self):
        """
        Retrieve all incidents.
        """

        if self.collection is None:
            return []

        incidents = list(
            self.collection.find({})
        )

        for incident in incidents:

            if "_id" in incident:
                incident["_id"] = str(
                    incident["_id"]
                )

        return incidents

    def get_incident(self, incident_id):
        """
        Retrieve an incident by ID.
        """

        if self.collection is None:
            return None

        incident = self.collection.find_one(
            {
                "incident_id": incident_id
            }
        )

        if incident and "_id" in incident:

            incident["_id"] = str(
                incident["_id"]
            )

        return incident

    def update_status(
        self,
        incident_id,
        status
    ):
        """
        Update incident status.
        """

        allowed_statuses = [
            "Open",
            "Investigating",
            "Resolved",
            "False Positive"
        ]

        if status not in allowed_statuses:

            raise ValueError(
                f"Invalid status. Allowed values: "
                f"{allowed_statuses}"
            )

        if self.collection is None:
            return None

        result = self.collection.update_one(
            {
                "incident_id": incident_id
            },
            {
                "$set": {
                    "status": status,
                    "updated_at": datetime.utcnow()
                }
            }
        )

        if result.matched_count == 0:
            return None

        return self.get_incident(
            incident_id
        )

    def correlate_events(self, events):
        """
        Correlate security events.
        """

        if not events:
            return []

        groups = correlate_events(events)

        result = []

        for group in groups:

            attack_chain = create_attack_chain(
                group
            )

            result.append({
                "event_count": len(group),
                "events": group,
                "attack_chain": attack_chain
            })

        return result