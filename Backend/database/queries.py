from datetime import datetime, timedelta

from database.mongodb import get_database


# =========================================================
# Database / Collections
# =========================================================

def get_collection(collection_name):
    """
    Return a MongoDB collection.
    """

    db = get_database()

    return db[collection_name]


# =========================================================
# Generic Insert
# =========================================================

def insert_document(
    collection_name,
    document
):
    """
    Insert one document into MongoDB.
    """

    collection = get_collection(
        collection_name
    )

    result = collection.insert_one(
        document
    )

    return str(
        result.inserted_id
    )


def insert_documents(
    collection_name,
    documents
):
    """
    Insert multiple documents.
    """

    if not documents:
        return []

    collection = get_collection(
        collection_name
    )

    result = collection.insert_many(
        documents
    )

    return [
        str(document_id)
        for document_id in result.inserted_ids
    ]


# =========================================================
# Generic Find
# =========================================================

def find_documents(
    collection_name,
    query=None,
    limit=100
):
    """
    Find documents from MongoDB.
    """

    collection = get_collection(
        collection_name
    )

    query = query or {}

    documents = list(
        collection.find(
            query
        )
        .limit(limit)
    )

    for document in documents:

        if "_id" in document:

            document["_id"] = str(
                document["_id"]
            )

    return documents


# =========================================================
# Assets
# =========================================================

def get_assets(limit=100):
    return find_documents(
        "assets",
        limit=limit
    )


def get_asset_by_id(asset_id):
    return find_documents(
        "assets",
        {
            "asset_id": asset_id
        },
        limit=1
    )


# =========================================================
# Vulnerabilities
# =========================================================

def get_vulnerabilities(limit=100):
    return find_documents(
        "vulnerabilities",
        limit=limit
    )


def get_vulnerabilities_by_asset(
    asset_id
):
    return find_documents(
        "vulnerabilities",
        {
            "asset_id": asset_id
        },
        limit=100
    )


# =========================================================
# Threats
# =========================================================

def get_threats(limit=100):
    return find_documents(
        "threats",
        limit=limit
    )


def get_threat_by_id(threat_id):
    return find_documents(
        "threats",
        {
            "threat_id": threat_id
        },
        limit=1
    )


# =========================================================
# Security Events
# =========================================================

def get_security_events(
    limit=100
):
    return find_documents(
        "security_events",
        limit=limit
    )


def get_security_event_by_id(
    event_id
):
    return find_documents(
        "security_events",
        {
            "event_id": event_id
        },
        limit=1
    )


# =========================================================
# Search Security Events
# =========================================================

def search_security_events(
    search_text,
    limit=100
):
    """
    Search event_id, asset_id, threat_id,
    source_ip, destination_ip, etc.
    """

    collection = get_collection(
        "security_events"
    )

    regex_query = {
        "$regex": search_text,
        "$options": "i"
    }

    query = {
        "$or": [
            {
                "event_id": regex_query
            },
            {
                "asset_id": regex_query
            },
            {
                "threat_id": regex_query
            },
            {
                "source_ip": regex_query
            },
            {
                "destination_ip": regex_query
            },
            {
                "event_type": regex_query
            },
            {
                "severity": regex_query
            }
        ]
    }

    documents = list(
        collection.find(
            query
        ).limit(limit)
    )

    for document in documents:

        document["_id"] = str(
            document["_id"]
        )

    return documents


# =========================================================
# Predictions
# =========================================================

def save_prediction(
    prediction
):
    """
    Store an ML prediction.
    """

    return insert_document(
        "predictions",
        prediction
    )


def save_predictions(
    predictions
):
    """
    Store multiple ML predictions.
    """

    return insert_documents(
        "predictions",
        predictions
    )


def get_predictions(
    limit=100
):
    return find_documents(
        "predictions",
        limit=limit
    )


def get_prediction_by_event(
    event_id
):
    return find_documents(
        "predictions",
        {
            "event_id": event_id
        },
        limit=1
    )


# =========================================================
# Anomalies
# =========================================================

def get_anomalies(
    limit=100
):
    """
    Get suspicious ML anomaly predictions.
    """

    return find_documents(
        "predictions",
        {
            "anomaly_status": "Suspicious"
        },
        limit=limit
    )


# =========================================================
# Threat Summary
# =========================================================

def get_threat_summary():
    """
    Return counts by risk level.
    """

    collection = get_collection(
        "predictions"
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

    summary = {}

    for result in results:

        summary[
            result["_id"] or "Unknown"
        ] = result["count"]

    return summary


# =========================================================
# Prediction Statistics
# =========================================================

def get_prediction_statistics():
    """
    Return prediction counts.
    """

    collection = get_collection(
        "predictions"
    )

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
        collection.aggregate(
            pipeline
        )
    )

    statistics = {}

    for result in results:

        statistics[
            result["_id"] or "Unknown"
        ] = result["count"]

    return statistics


# =========================================================
# Threat Timeline
# =========================================================

def get_threat_timeline(
    days=7
):
    """
    Return threat activity grouped by date.
    """

    collection = get_collection(
        "predictions"
    )

    start_date = (
        datetime.utcnow()
        - timedelta(days=days)
    )

    pipeline = [
        {
            "$match": {
                "created_at": {
                    "$gte": start_date
                }
            }
        },
        {
            "$group": {
                "_id": {
                    "$dateToString": {
                        "format": "%Y-%m-%d",
                        "date": "$created_at"
                    }
                },
                "total_events": {
                    "$sum": 1
                },
                "suspicious_events": {
                    "$sum": {
                        "$cond": [
                            {
                                "$eq": [
                                    "$prediction",
                                    "Suspicious"
                                ]
                            },
                            1,
                            0
                        ]
                    }
                }
            }
        },
        {
            "$sort": {
                "_id": 1
            }
        }
    ]

    return list(
        collection.aggregate(
            pipeline
        )
    )


# =========================================================
# Heatmap of Attacks
# =========================================================

def get_attack_heatmap():
    """
    Generate attack counts grouped by
    day of week and hour.
    """

    collection = get_collection(
        "predictions"
    )

    pipeline = [
        {
            "$match": {
                "created_at": {
                    "$exists": True
                }
            }
        },
        {
            "$project": {
                "hour": {
                    "$hour": "$created_at"
                },
                "day": {
                    "$dayOfWeek": "$created_at"
                },
                "prediction": 1
            }
        },
        {
            "$match": {
                "prediction": "Suspicious"
            }
        },
        {
            "$group": {
                "_id": {
                    "day": "$day",
                    "hour": "$hour"
                },
                "count": {
                    "$sum": 1
                }
            }
        },
        {
            "$sort": {
                "_id.day": 1,
                "_id.hour": 1
            }
        }
    ]

    return list(
        collection.aggregate(
            pipeline
        )
    )


# =========================================================
# Top Targeted Assets
# =========================================================

def get_top_targeted_assets(
    limit=10
):
    """
    Find the assets associated with
    the most suspicious events.
    """

    collection = get_collection(
        "predictions"
    )

    pipeline = [
        {
            "$match": {
                "prediction": "Suspicious",
                "asset_id": {
                    "$exists": True
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

    return list(
        collection.aggregate(
            pipeline
        )
    )


# =========================================================
# Model Performance
# =========================================================

def save_model_performance(
    performance
):
    """
    Save ML model evaluation results.
    """

    return insert_document(
        "model_performance",
        performance
    )


def get_model_performance():
    """
    Return latest model performance.
    """

    collection = get_collection(
        "model_performance"
    )

    documents = list(
        collection.find()
        .sort(
            "created_at",
            -1
        )
        .limit(10)
    )

    for document in documents:

        document["_id"] = str(
            document["_id"]
        )

    return documents