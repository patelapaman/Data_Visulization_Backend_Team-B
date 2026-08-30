from database.queries import (
    get_dashboard_summary,
    get_high_risk_assets,
    get_features
)
<<<<<<< HEAD
=======
from services.addon_service import overview_analytics
>>>>>>> fef0746 (Milestone 3)


def get_dashboard_analytics():
    """
    Return analytics required for the dashboard.
    """

    summary = get_dashboard_summary()

    high_risk_assets = get_high_risk_assets()

    engineered_features = get_features()

    analytics = {
        "summary": summary,
        "high_risk_assets": high_risk_assets,
<<<<<<< HEAD
        "feature_count": len(engineered_features)
=======
        "feature_count": len(engineered_features),
        "event_analytics": overview_analytics(),
>>>>>>> fef0746 (Milestone 3)
    }

    return analytics
"""
Analytics Service

Provides dashboard analytics for:
- Threat statistics
- Risk levels
- Incident statistics
- Threat timeline
- Attack heatmap
- Top targeted assets
- ML prediction statistics
"""

from datetime import datetime, timedelta

from database.mongodb import get_database


class AnalyticsService:

    def __init__(self):
        self.db = get_database()

        self.events_collection = self.db[
            "security_events"
        ]

        self.incidents_collection = self.db[
            "incidents"
        ]

        self.predictions_collection = self.db[
            "predictions"
        ]

    # ---------------------------------------------------------
    # Dashboard Summary
    # ---------------------------------------------------------

    def get_dashboard_summary(self):
        """
        Return overall dashboard statistics.
        """

        total_events = self.events_collection.count_documents({})

        total_incidents = (
            self.incidents_collection.count_documents({})
        )

        open_incidents = (
            self.incidents_collection.count_documents(
                {
                    "status": {
                        "$in": [
                            "Open",
                            "Investigating"
                        ]
                    }
                }
            )
        )

        critical_incidents = (
            self.incidents_collection.count_documents(
                {
                    "risk_level": "Critical"
                }
            )
        )

        high_risk_incidents = (
            self.incidents_collection.count_documents(
                {
                    "risk_level": {
                        "$in": [
                            "Critical",
                            "High"
                        ]
                    }
                }
            )
        )

        total_predictions = (
            self.predictions_collection.count_documents({})
        )

        return {
            "total_events": total_events,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "critical_incidents": critical_incidents,
            "high_risk_incidents": high_risk_incidents,
            "total_predictions": total_predictions
        }

    # ---------------------------------------------------------
    # Risk Distribution
    # ---------------------------------------------------------

    def get_risk_distribution(self):
        """
        Return number of incidents by risk level.
        """

        pipeline = [
            {
                "$group": {
                    "_id": "$risk_level",
                    "count": {
                        "$sum": 1
                    }
                }
            }
        ]

        results = list(
            self.incidents_collection.aggregate(
                pipeline
            )
        )

        distribution = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }

        for result in results:

            level = result.get("_id")

            if level in distribution:
                distribution[level] = result["count"]

        return distribution

    # ---------------------------------------------------------
    # Incident Status
    # ---------------------------------------------------------

    def get_incident_status_distribution(self):
        """
        Return incidents grouped by status.
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
            self.incidents_collection.aggregate(
                pipeline
            )
        )

        distribution = {}

        for result in results:

            distribution[result["_id"]] = (
                result["count"]
            )

        return distribution

    # ---------------------------------------------------------
    # Threat Timeline
    # ---------------------------------------------------------

    def get_threat_timeline(
        self,
        days=7
    ):
        """
        Return number of security events per day.
        """

        start_date = datetime.utcnow() - timedelta(
            days=days
        )

        pipeline = [
            {
                "$match": {
                    "timestamp": {
                        "$gte": start_date
                    }
                }
            },
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%d",
                            "date": "$timestamp"
                        }
                    },
                    "count": {
                        "$sum": 1
                    }
                }
            },
            {
                "$sort": {
                    "_id": 1
                }
            }
        ]

        results = list(
            self.events_collection.aggregate(
                pipeline
            )
        )

        return [
            {
                "date": result["_id"],
                "count": result["count"]
            }
            for result in results
        ]

    # ---------------------------------------------------------
    # Attack Heatmap
    # ---------------------------------------------------------

    def get_attack_heatmap(self):
        """
        Generate attack distribution by source and
        destination.
        """

        pipeline = [
            {
                "$group": {
                    "_id": {
                        "source": "$source_ip",
                        "destination": "$destination_ip"
                    },
                    "count": {
                        "$sum": 1
                    }
                }
            }
        ]

        results = list(
            self.events_collection.aggregate(
                pipeline
            )
        )

        heatmap = []

        for result in results:

            values = result["_id"]

            heatmap.append({
                "source_ip": values.get(
                    "source"
                ),
                "destination_ip": values.get(
                    "destination"
                ),
                "count": result["count"]
            })

        return heatmap

    # ---------------------------------------------------------
    # Top Targeted Assets
    # ---------------------------------------------------------

    def get_top_targeted_assets(
        self,
        limit=10
    ):
        """
        Return assets receiving the most attacks.
        """

        pipeline = [
            {
                "$match": {
                    "asset_id": {
                        "$exists": True,
                        "$ne": None
                    }
                }
            },
            {
                "$group": {
                    "_id": "$asset_id",
                    "attack_count": {
                        "$sum": 1
                    }
                }
            },
            {
                "$sort": {
                    "attack_count": -1
                }
            },
            {
                "$limit": limit
            }
        ]

        results = list(
            self.events_collection.aggregate(
                pipeline
            )
        )

        return [
            {
                "asset_id": result["_id"],
                "attack_count": result[
                    "attack_count"
                ]
            }
            for result in results
        ]

    # ---------------------------------------------------------
    # Threat Types
    # ---------------------------------------------------------

    def get_threat_type_distribution(self):
        """
        Return number of events by threat type.
        """

        pipeline = [
            {
                "$group": {
                    "_id": "$event_type",
                    "count": {
                        "$sum": 1
                    }
                }
            },
            {
                "$sort": {
                    "count": -1
                }
            }
        ]

        results = list(
            self.events_collection.aggregate(
                pipeline
            )
        )

        return [
            {
                "threat_type": result["_id"],
                "count": result["count"]
            }
            for result in results
        ]

    # ---------------------------------------------------------
    # ML Prediction Statistics
    # ---------------------------------------------------------

    def get_prediction_statistics(self):
        """
        Return ML prediction distribution.
        """

        pipeline = [
            {
                "$group": {
                    "_id": "$prediction",
                    "count": {
                        "$sum": 1
                    }
                }
            }
        ]

        results = list(
            self.predictions_collection.aggregate(
                pipeline
            )
        )

        statistics = {}

        for result in results:

            statistics[result["_id"]] = (
                result["count"]
            )

        return statistics

    # ---------------------------------------------------------
    # MITRE Techniques
    # ---------------------------------------------------------

    def get_mitre_distribution(self):
        """
        Return attack distribution by MITRE technique.
        """

        pipeline = [
            {
                "$match": {
                    "mitre_technique": {
                        "$exists": True,
                        "$ne": None
                    }
                }
            },
            {
                "$group": {
                    "_id": "$mitre_technique",
                    "count": {
                        "$sum": 1
                    }
                }
            },
            {
                "$sort": {
                    "count": -1
                }
            }
        ]

        results = list(
            self.events_collection.aggregate(
                pipeline
            )
        )

        return [
            {
                "mitre_technique": result["_id"],
                "count": result["count"]
            }
            for result in results
        ]

    # ---------------------------------------------------------
    # Complete Dashboard Analytics
    # ---------------------------------------------------------

    def get_dashboard_analytics(self):
        """
        Return all dashboard analytics in one response.
        """

        return {
            "summary": self.get_dashboard_summary(),

            "risk_distribution":
                self.get_risk_distribution(),

            "incident_status":
                self.get_incident_status_distribution(),

            "threat_timeline":
                self.get_threat_timeline(),

            "attack_heatmap":
                self.get_attack_heatmap(),

            "top_targeted_assets":
                self.get_top_targeted_assets(),

            "threat_types":
                self.get_threat_type_distribution(),

            "prediction_statistics":
                self.get_prediction_statistics(),

            "mitre_distribution":
                self.get_mitre_distribution()
        }

