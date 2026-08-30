from flask import Blueprint, request, jsonify

from database.mongodb import get_database


intelligence_bp = Blueprint(
    "intelligence",
    __name__,
    url_prefix="/api/intelligence"
)


def get_collection():
    """
    Get MongoDB threat intelligence collection.
    """

    db = get_database()

    return db["threat_intelligence"]


@intelligence_bp.route("", methods=["GET"])
def get_threat_intelligence():
    """
    Return threat intelligence records.
    """

    try:

        collection = get_collection()

        records = list(
            collection.find(
                {},
                {"_id": 0}
            ).limit(100)
        )

        return jsonify({
            "success": True,
            "count": len(records),
            "data": records
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@intelligence_bp.route("/search", methods=["GET"])
def search_intelligence():
    """
    Search threat intelligence.

    Examples:

    /api/intelligence/search?ioc=1.2.3.4

    /api/intelligence/search?threat_id=THREAT-001
    """

    try:

        collection = get_collection()

        query = {}

        ioc = request.args.get("ioc")
        threat_id = request.args.get("threat_id")
        threat_actor = request.args.get(
            "threat_actor"
        )

        if ioc:
            query["ioc"] = ioc

        if threat_id:
            query["threat_id"] = threat_id

        if threat_actor:
            query["threat_actor"] = threat_actor

        records = list(
            collection.find(
                query,
                {"_id": 0}
            ).limit(100)
        )

        return jsonify({
            "success": True,
            "count": len(records),
            "query": query,
            "data": records
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@intelligence_bp.route("/ioc/<ioc>", methods=["GET"])
def get_ioc_information(ioc):
    """
    Search information for a specific IOC.
    """

    try:

        collection = get_collection()

        record = collection.find_one(
            {"ioc": ioc},
            {"_id": 0}
        )

        if not record:

            return jsonify({
                "success": False,
                "message": "IOC not found"
            }), 404

        return jsonify({
            "success": True,
            "data": record
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@intelligence_bp.route("/mitre/<technique_id>", methods=["GET"])
def get_mitre_information(technique_id):
    """
    Get MITRE ATT&CK information.
    """

    try:

        db = get_database()

        collection = db["mitre"]

        record = collection.find_one(
            {
                "$or": [
                    {"technique_id": technique_id},
                    {"mitre_technique": technique_id}
                ]
            },
            {"_id": 0}
        )

        if not record:

            return jsonify({
                "success": False,
                "message": "MITRE technique not found"
            }), 404

        return jsonify({
            "success": True,
            "data": record
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500