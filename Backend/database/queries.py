<<<<<<< HEAD
from database.mongodb import get_db


def get_collection(collection_name):
    """Return all documents from a MongoDB collection."""
    db = get_db()
    return list(db[collection_name].find({}, {"_id": 0}))


def get_assets():
    return get_collection("assets")


def get_vulnerabilities():
    return get_collection("vulnerabilities")


def get_security_events():
    """Return security telemetry directly from MongoDB."""
    return get_collection("security_events")


def get_incidents():
    return get_collection("incident_history")


def get_threats():
    return get_collection("threat_intelligence")


def get_mitre():
    return get_collection("mitre_mapping")


def get_enriched_events():
    return get_collection("enriched_events")


def get_mapped_events():
    return get_collection("mapped_events")


def get_features():
    return get_collection("engineered_features")


def get_high_risk_assets():
    db = get_db()
    return list(db["engineered_features"].find(
        {"risk_category": {"$in": ["High", "Critical"]}},
        {"_id": 0}
    ))


def get_dashboard_summary():
    db = get_db()
    return {
        "assets": db["assets"].count_documents({}),
        "vulnerabilities": db["vulnerabilities"].count_documents({}),
        "security_events": db["security_events"].count_documents({}),
        "incidents": db["incident_history"].count_documents({}),
        "threats": db["threat_intelligence"].count_documents({}),
        "mapped_events": db["mapped_events"].count_documents({}),
        "high_risk_assets": db["engineered_features"].count_documents(
            {"risk_category": {"$in": ["High", "Critical"]}}
        )
    }
=======

"""
Database Queries

Centralized MongoDB queries for:
- Security events
- Threats
- Vulnerabilities
- Assets
- Incidents
- Predictions
- Threat intelligence
- Dashboard analytics
"""

from datetime import datetime, timedelta

from database.mongodb import get_database


# ---------------------------------------------------------
# Database Helper
# ---------------------------------------------------------

def get_collection(collection_name):
    """
    Return a MongoDB collection.
    """

    db = get_database()

    return db[collection_name]


# =========================================================
# SECURITY EVENTS
# =========================================================

def get_security_events(
    limit=100,
    skip=0
):
    """
    Get security events.
    """

    collection = get_collection(
        "security_events"
    )

    return list(
        collection.find(
            {},
            {"_id": 0}
        )
        .sort("timestamp", -1)
        .skip(skip)
        .limit(limit)
    )


def get_security_event(event_id):
    """
    Get a security event by event ID.
    """

    collection = get_collection(
        "security_events"
    )

    return collection.find_one(
        {
            "event_id": event_id
        },
        {
            "_id": 0
        }
    )


def search_security_events(
    search_term,
    limit=100
):
    """
    Search security events.
    """

    collection = get_collection(
        "security_events"
    )

    query = {
        "$or": [
            {
                "event_id": {
                    "$regex": search_term,
                    "$options": "i"
                }
            },
            {
                "event_type": {
                    "$regex": search_term,
                    "$options": "i"
                }
            },
            {
                "asset_id": {
                    "$regex": search_term,
                    "$options": "i"
                }
            },
            {
                "source_ip": {
                    "$regex": search_term,
                    "$options": "i"
                }
            }
        ]
    }

    return list(
        collection.find(
            query,
            {"_id": 0}
        )
        .limit(limit)
    )


# =========================================================
# ASSETS
# =========================================================

def get_assets(
    limit=100
):
    """
    Get assets.
    """

    collection = get_collection(
        "assets"
    )

    return list(
        collection.find(
            {},
            {"_id": 0}
        ).limit(limit)
    )


def get_asset(asset_id):
    """
    Get asset by ID.
    """

    collection = get_collection(
        "assets"
    )

    return collection.find_one(
        {
            "asset_id": asset_id
        },
        {
            "_id": 0
        }
    )


# =========================================================
# VULNERABILITIES
# =========================================================

def get_vulnerabilities(
    limit=100
):
    """
    Get vulnerabilities.
    """

    collection = get_collection(
        "vulnerabilities"
    )

    return list(
        collection.find(
            {},
            {"_id": 0}
        ).limit(limit)
    )


def get_asset_vulnerabilities(
    asset_id
):
    """
    Get vulnerabilities affecting an asset.
    """

    collection = get_collection(
        "vulnerabilities"
    )

    return list(
        collection.find(
            {
                "asset_id": asset_id
            },
            {
                "_id": 0
            }
        )
    )


# =========================================================
# THREATS
# =========================================================

def get_threats(
    limit=100
):
    """
    Get threats.
    """

    collection = get_collection(
        "threats"
    )

    return list(
        collection.find(
            {},
            {"_id": 0}
        ).limit(limit)
    )


def get_threat(threat_id):
    """
    Get threat by ID.
    """

    collection = get_collection(
        "threats"
    )

    return collection.find_one(
        {
            "threat_id": threat_id
        },
        {
            "_id": 0
        }
    )


# =========================================================
# INCIDENTS
# =========================================================

def get_incidents(
    limit=100
):
    """
    Get incidents.
    """

    collection = get_collection(
        "incidents"
    )

    return list(
        collection.find(
            {},
            {"_id": 0}
        )
        .sort("created_at", -1)
        .limit(limit)
    )


def get_incident(incident_id):
    """
    Get incident by incident ID.
    """

    collection = get_collection(
        "incidents"
    )

    return collection.find_one(
        {
            "incident_id": incident_id
        },
        {
            "_id": 0
        }
    )


def get_open_incidents(
    limit=100
):
    """
    Get open and investigating incidents.
    """

    collection = get_collection(
        "incidents"
    )

    return list(
        collection.find(
            {
                "status": {
                    "$in": [
                        "Open",
                        "Investigating"
                    ]
                }
            },
            {
                "_id": 0
            }
        )
        .sort("risk_score", -1)
        .limit(limit)
    )


def get_high_risk_incidents(
    minimum_score=61,
    limit=100
):
    """
    Get high-risk incidents.
    """

    collection = get_collection(
        "incidents"
    )

    return list(
        collection.find(
            {
                "risk_score": {
                    "$gte": minimum_score
                }
            },
            {
                "_id": 0
            }
        )
        .sort("risk_score", -1)
        .limit(limit)
    )


def update_incident_status(
    incident_id,
    status
):
    """
    Update incident status.
    """

    collection = get_collection(
        "incidents"
    )

    result = collection.update_one(
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

    return result.modified_count > 0


# =========================================================
# PREDICTIONS
# =========================================================

def get_predictions(
    limit=100
):
    """
    Get ML predictions.
    """

    collection = get_collection(
        "predictions"
    )

    return list(
        collection.find(
            {},
            {"_id": 0}
        )
        .sort("created_at", -1)
        .limit(limit)
    )


def get_prediction_by_event(
    event_id
):
    """
    Get prediction associated with an event.
    """

    collection = get_collection(
        "predictions"
    )

    return collection.find_one(
        {
            "event_id": event_id
        },
        {
            "_id": 0
        }
    )


# =========================================================
# THREAT INTELLIGENCE
# =========================================================

def get_threat_intelligence(
    limit=100
):
    """
    Get threat intelligence records.
    """

    collection = get_collection(
        "threat_intelligence"
    )

    return list(
        collection.find(
            {},
            {"_id": 0}
        ).limit(limit)
    )


def search_threat_intelligence(
    ioc=None,
    threat_id=None,
    threat_actor=None
):
    """
    Search threat intelligence.
    """

    collection = get_collection(
        "threat_intelligence"
    )

    query = {}

    if ioc:
        query["ioc"] = ioc

    if threat_id:
        query["threat_id"] = threat_id

    if threat_actor:
        query["threat_actor"] = threat_actor

    return list(
        collection.find(
            query,
            {"_id": 0}
        ).limit(100)
    )


def get_ioc(ioc):
    """
    Get threat intelligence for an IOC.
    """

    collection = get_collection(
        "threat_intelligence"
    )

    return collection.find_one(
        {
            "ioc": ioc
        },
        {
            "_id": 0
        }
    )


# =========================================================
# MITRE ATT&CK
# =========================================================

def get_mitre_technique(
    technique_id
):
    """
    Get MITRE ATT&CK technique.
    """

    collection = get_collection(
        "mitre"
    )

    return collection.find_one(
        {
            "$or": [
                {
                    "technique_id":
                        technique_id
                },
                {
                    "mitre_technique":
                        technique_id
                },
                {
                    "id":
                        technique_id
                }
            ]
        },
        {
            "_id": 0
        }
    )


# =========================================================
# DASHBOARD ANALYTICS
# =========================================================

def count_security_events():
    """
    Count security events.
    """

    collection = get_collection(
        "security_events"
    )

    return collection.count_documents({})


def count_incidents():
    """
    Count incidents.
    """

    collection = get_collection(
        "incidents"
    )

    return collection.count_documents({})


def count_open_incidents():
    """
    Count open incidents.
    """

    collection = get_collection(
        "incidents"
    )

    return collection.count_documents(
        {
            "status": {
                "$in": [
                    "Open",
                    "Investigating"
                ]
            }
        }
    )


def get_incident_status_counts():
    """
    Count incidents by status.
    """

    collection = get_collection(
        "incidents"
    )

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
        collection.aggregate(
            pipeline
        )
    )

    return {
        result["_id"]: result["count"]
        for result in results
    }


def get_risk_level_counts():
    """
    Count incidents by risk level.
    """

    collection = get_collection(
        "incidents"
    )

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
        collection.aggregate(
            pipeline
        )
    )

    return {
        result["_id"]: result["count"]
        for result in results
    }


def get_top_targeted_assets(
    limit=10
):
    """
    Get assets with the highest number
    of security events.
    """

    collection = get_collection(
        "security_events"
    )

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
        collection.aggregate(
            pipeline
        )
    )

    return [
        {
            "asset_id": result["_id"],
            "attack_count":
                result["attack_count"]
        }
        for result in results
    ]


def get_attack_heatmap():
    """
    Get attack distribution between
    source and destination IPs.
    """

    collection = get_collection(
        "security_events"
    )

    pipeline = [
        {
            "$group": {
                "_id": {
                    "source":
                        "$source_ip",
                    "destination":
                        "$destination_ip"
                },
                "count": {
                    "$sum": 1
                }
            }
        }
    ]

    results = list(
        collection.aggregate(
            pipeline
        )
    )

    return [
        {
            "source_ip":
                result["_id"].get(
                    "source"
                ),
            "destination_ip":
                result["_id"].get(
                    "destination"
                ),
            "count":
                result["count"]
        }
        for result in results
    ]


def get_threat_timeline(
    days=7
):
    """
    Get event count by day.
    """

    collection = get_collection(
        "security_events"
    )

    start_date = (
        datetime.utcnow()
        - timedelta(days=days)
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
                        "format":
                            "%Y-%m-%d",
                        "date":
                            "$timestamp"
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
        collection.aggregate(
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

>>>>>>> fef0746 (Milestone 3)
