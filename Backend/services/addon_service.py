"""Analytics and export services used by the add-on API endpoints."""

from database.queries import aggregate_events


def _count_group(field, event_filter=None, limit=25):
    pipeline = []
    if event_filter:
        pipeline.append({"$match": event_filter})
    pipeline.extend(
        [
            {"$group": {"_id": {"$ifNull": [f"${field}", "Unknown"]}, "count": {"$sum": 1}}},
            {"$sort": {"count": -1, "_id": 1}},
            {"$limit": limit},
            {"$project": {"_id": 0, "label": "$_id", "count": 1}},
        ]
    )
    return aggregate_events(pipeline)


def threat_timeline(event_filter=None, interval="day"):
    date_format = "%Y-%m-%d" if interval == "day" else "%Y-%m"
    pipeline = []
    if event_filter:
        pipeline.append({"$match": event_filter})
    pipeline.extend(
        [
            {
                "$project": {
                    "period": {
                        "$dateToString": {
                            "format": date_format,
                            "date": {
                                "$convert": {
                                    "input": "$timestamp",
                                    "to": "date",
                                    "onError": None,
                                    "onNull": None,
                                }
                            },
                        }
                    },
                    "severity": {"$ifNull": ["$severity", "Unknown"]},
                    "risk_score": {"$convert": {"input": "$risk_score", "to": "double", "onError": 0}},
                }
            },
            {"$match": {"period": {"$ne": None}}},
            {
                "$group": {
                    "_id": "$period",
                    "events": {"$sum": 1},
                    "high_risk_events": {
                        "$sum": {"$cond": [{"$gte": ["$risk_score", 75]}, 1, 0]}
                    },
                    "critical_events": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "Critical"]}, 1, 0]}
                    },
                    "average_risk_score": {"$avg": "$risk_score"},
                }
            },
            {"$sort": {"_id": 1}},
            {
                "$project": {
                    "_id": 0,
                    "period": "$_id",
                    "events": 1,
                    "high_risk_events": 1,
                    "critical_events": 1,
                    "average_risk_score": {"$round": ["$average_risk_score", 2]},
                }
            },
        ]
    )
    return aggregate_events(pipeline)


def top_targeted_assets(event_filter=None, limit=10):
    pipeline = []
    if event_filter:
        pipeline.append({"$match": event_filter})
    pipeline.extend(
        [
            {
                "$project": {
                    "asset": {
                        "$ifNull": [
                            "$asset_name",
                            {"$ifNull": ["$device_name", {"$ifNull": ["$destination_ip", "Unknown"]}]},
                        ]
                    },
                    "severity": {"$ifNull": ["$severity", "Unknown"]},
                    "risk_score": {"$convert": {"input": "$risk_score", "to": "double", "onError": 0}},
                }
            },
            {
                "$group": {
                    "_id": "$asset",
                    "event_count": {"$sum": 1},
                    "average_risk_score": {"$avg": "$risk_score"},
                    "critical_events": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "Critical"]}, 1, 0]}
                    },
                }
            },
            {"$sort": {"event_count": -1, "average_risk_score": -1}},
            {"$limit": limit},
            {
                "$project": {
                    "_id": 0,
                    "asset": "$_id",
                    "event_count": 1,
                    "critical_events": 1,
                    "average_risk_score": {"$round": ["$average_risk_score", 2]},
                }
            },
        ]
    )
    return aggregate_events(pipeline)


def heatmap_data(event_filter=None):
    pipeline = []
    if event_filter:
        pipeline.append({"$match": event_filter})
    pipeline.extend(
        [
            {
                "$project": {
                    "source_country": {"$ifNull": ["$source_country", "Unknown"]},
                    "destination_country": {"$ifNull": ["$destination_country", "Unknown"]},
                    "severity": {"$ifNull": ["$severity", "Unknown"]},
                    "risk_score": {"$convert": {"input": "$risk_score", "to": "double", "onError": 0}},
                }
            },
            {
                "$group": {
                    "_id": {
                        "source": "$source_country",
                        "destination": "$destination_country",
                    },
                    "event_count": {"$sum": 1},
                    "risk_score": {"$sum": "$risk_score"},
                    "critical_events": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "Critical"]}, 1, 0]}
                    },
                }
            },
            {"$sort": {"event_count": -1}},
            {
                "$project": {
                    "_id": 0,
                    "source_country": "$_id.source",
                    "destination_country": "$_id.destination",
                    "event_count": 1,
                    "risk_score": 1,
                    "critical_events": 1,
                }
            },
        ]
    )
    return aggregate_events(pipeline)


def overview_analytics(event_filter=None):
    return {
        "severity": _count_group("severity", event_filter),
        "event_types": _count_group("event_type", event_filter),
        "statuses": _count_group("event_status", event_filter),
        "source_countries": _count_group("source_country", event_filter),
        "destination_countries": _count_group("destination_country", event_filter),
        "mitre_techniques": _count_group("mitre_id", event_filter),
        "top_users": _count_group("username", event_filter, limit=10),
        "top_targeted_assets": top_targeted_assets(event_filter, limit=10),
    }