"""
Incident Repository

Handles all MongoDB operations related
to security incidents.
"""

from datetime import datetime
from database.mongodb import get_database


class IncidentRepository:

    def __init__(self, collection_name="incidents"):
        self.db = get_database()
        self.collection = self.db[collection_name]

    def create_incident(self, incident):
        """
        Insert a new incident into MongoDB.
        """

        if not incident:
            raise ValueError("Incident data is required")

        incident = incident.copy()

        incident["created_at"] = datetime.utcnow()

        if "status" not in incident:
            incident["status"] = "Open"

        result = self.collection.insert_one(
            incident
        )

        incident["_id"] = str(
            result.inserted_id
        )

        return incident

    def get_all_incidents(
        self,
        limit=100
    ):
        """
        Retrieve all incidents.
        """

        incidents = list(
            self.collection.find(
                {}
            )
            .sort("created_at", -1)
            .limit(limit)
        )

        for incident in incidents:

            if "_id" in incident:
                incident["_id"] = str(
                    incident["_id"]
                )

        return incidents

    def get_incident(
        self,
        incident_id
    ):
        """
        Retrieve incident using incident_id.
        """

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

    def get_incident_by_event(
        self,
        event_id
    ):
        """
        Find an incident associated
        with a particular security event.
        """

        incident = self.collection.find_one(
            {
                "event_id": event_id
            }
        )

        if incident and "_id" in incident:
            incident["_id"] = str(
                incident["_id"]
            )

        return incident

    def update_incident(
        self,
        incident_id,
        update_data
    ):
        """
        Update incident information.
        """

        update_data = update_data.copy()

        update_data["updated_at"] = datetime.utcnow()

        result = self.collection.update_one(
            {
                "incident_id": incident_id
            },
            {
                "$set": update_data
            }
        )

        if result.matched_count == 0:
            return None

        return self.get_incident(
            incident_id
        )

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
                "Invalid incident status"
            )

        return self.update_incident(
            incident_id,
            {
                "status": status
            }
        )

    def delete_incident(
        self,
        incident_id
    ):
        """
        Delete an incident.
        """

        result = self.collection.delete_one(
            {
                "incident_id": incident_id
            }
        )

        return result.deleted_count > 0

    def count_by_status(self):
        """
        Return incident counts grouped by status.
        """

        pipeline = [
            {
                "$group": {
                    "_id": "$status",
                    "count": {
                        "$sum": 1
                    }
                }
            }
        ]

        results = list(
            self.collection.aggregate(
                pipeline
            )
        )

        output = {}

        for item in results:

            output[item["_id"]] = item["count"]

        return output

    def get_high_risk_incidents(
        self,
        minimum_score=61,
        limit=100
    ):
        """
        Return high-risk incidents.
        """

        incidents = list(
            self.collection.find(
                {
                    "risk_score": {
                        "$gte": minimum_score
                    }
                }
            )
            .sort("risk_score", -1)
            .limit(limit)
        )

        for incident in incidents:

            if "_id" in incident:
                incident["_id"] = str(
                    incident["_id"]
                )

        return incidents