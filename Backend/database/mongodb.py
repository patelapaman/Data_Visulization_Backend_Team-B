<<<<<<< HEAD
from __future__ import annotations

from pathlib import Path
from typing import Any
import os

import pandas as pd
from bson import ObjectId
from pymongo import MongoClient
from pymongo.errors import PyMongoError

from config import Config

client: MongoClient | None = None
db = None
_mongodb_connected = False
=======

"""
MongoDB Database Connection

Handles:
- MongoDB connection
- Database access
- Connection testing
- Environment configuration
"""

import os
from urllib.parse import quote_plus

from pymongo import MongoClient
from pymongo.errors import (
    PyMongoError,
    ServerSelectionTimeoutError
)
from dotenv import load_dotenv


# ---------------------------------------------------------
# Load Environment Variables
# ---------------------------------------------------------

load_dotenv()


# ---------------------------------------------------------
# MongoDB Configuration
# ---------------------------------------------------------

MONGO_URI = os.getenv("MONGO_URI")

MONGO_USERNAME = os.getenv(
    "MONGO_USERNAME"
)

MONGO_PASSWORD = os.getenv(
    "MONGO_PASSWORD"
)

MONGO_CLUSTER = os.getenv(
    "MONGO_CLUSTER"
)

MONGO_DATABASE = os.getenv(
    "MONGO_DATABASE",
    "threat_detection"
)


# ---------------------------------------------------------
# Build MongoDB URI
# ---------------------------------------------------------

if not MONGO_URI:

    if (
        MONGO_USERNAME
        and MONGO_PASSWORD
        and MONGO_CLUSTER
    ):

        encoded_username = quote_plus(
            MONGO_USERNAME
        )
>>>>>>> fef0746 (Milestone 3)

        encoded_password = quote_plus(
            MONGO_PASSWORD
        )

        MONGO_URI = (
            f"mongodb+srv://"
            f"{encoded_username}:"
            f"{encoded_password}@"
            f"{MONGO_CLUSTER}/"
            f"?retryWrites=true&w=majority"
        )

    else:

        MONGO_URI = "mongodb://localhost:27017"


# ---------------------------------------------------------
# MongoDB Client
# ---------------------------------------------------------

client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000
)


# ---------------------------------------------------------
# Get Database
# ---------------------------------------------------------

<<<<<<< HEAD
def _clean_value(value: Any):
    """Convert pandas/numpy values into BSON-safe Python values."""
    if pd.isna(value) if not isinstance(value, (list, dict, tuple)) else False:
        return None
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass
    return value


def _data_dir() -> Path:
    return Path(__file__).resolve().parents[1] / Config.UPLOAD_FOLDER


CSV_COLLECTIONS = {
    "assets": "assets.csv",
    "security_events": "security_events.csv",
    "vulnerabilities": "vulnerabilities.csv",
    "threat_intelligence": "threat_intelligence.csv",
    "incident_history": "incident_history.csv",
    "mitre_mapping": "mitre_attack_mapping.csv",
}


def _csv_records(filename: str) -> list[dict]:
    path = _data_dir() / filename
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    frame = pd.read_csv(path)
    frame = frame.astype(object).where(pd.notna(frame), None)
    records = []
    for row in frame.to_dict("records"):
        records.append({str(k): _clean_value(v) for k, v in row.items()})
    return records


def seed_csv_collections(force: bool = False) -> dict[str, int]:
    """Load bundled CSV datasets into MongoDB collections.

    By default, existing collections are preserved. With force=True the six
    bundled source collections are replaced with the CSV contents.
    """
    if not _mongodb_connected or db is None:
        raise RuntimeError("MongoDB is not connected. Start MongoDB or configure MONGO_URI.")

    counts: dict[str, int] = {}
    for collection_name, filename in CSV_COLLECTIONS.items():
        collection = db[collection_name]
        records = _csv_records(filename)
        if force:
            collection.delete_many({})
        if collection.count_documents({}) == 0 and records:
            collection.insert_many(records, ordered=False)
        counts[collection_name] = collection.count_documents({})

    # Helpful indexes for the application's lookup patterns.
    if db["security_events"].count_documents({}) > 0:
        db["security_events"].create_index("event_id", unique=True, sparse=True)
        db["security_events"].create_index("source_ip")
        db["security_events"].create_index("destination_ip")
        db["security_events"].create_index("timestamp")
    if db["vulnerabilities"].count_documents({}) > 0:
        db["vulnerabilities"].create_index("vulnerability_id", unique=True, sparse=True)
    if db["incident_history"].count_documents({}) > 0:
        db["incident_history"].create_index("incident_id", unique=True, sparse=True)
    return counts


def connect_db(app=None):
    """Connect to MongoDB and seed bundled datasets on first run.

    MongoDB is intentionally required in this version so the dashboard never
    silently reports data from an in-memory fallback when the user expects a
    real database.
    """
    global client, db, _mongodb_connected

    uri = Config.MONGO_URI
    timeout_ms = int(os.getenv("MONGO_SERVER_SELECTION_TIMEOUT_MS", "5000"))
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=timeout_ms)
        client.admin.command("ping")
        db = client[Config.DATABASE_NAME]
        _mongodb_connected = True
        print(f"MongoDB connected: {Config.DATABASE_NAME}")

        if Config.AUTO_SEED_MONGODB:
            counts = seed_csv_collections(force=Config.FORCE_SEED_MONGODB)
            print("MongoDB dataset status:", counts)
    except Exception as exc:
        client = None
        db = None
        _mongodb_connected = False
        message = (
            "MongoDB connection failed. Start MongoDB (or set a valid MONGO_URI) "
            f"and restart the backend. Details: {exc}"
        )
        print(message)
        if Config.REQUIRE_MONGODB:
            raise RuntimeError(message) from exc
=======
def get_database():
    """
    Return the MongoDB database instance.
    """
>>>>>>> fef0746 (Milestone 3)

    return client[MONGO_DATABASE]


# ---------------------------------------------------------
# Backward-Compatible Alias
# ---------------------------------------------------------

def get_db():
<<<<<<< HEAD
    if db is None:
        raise RuntimeError("MongoDB is not connected.")
    return db
=======
    """
    Alias for get_database().
    """
>>>>>>> fef0746 (Milestone 3)

    return get_database()


# ---------------------------------------------------------
# Connect Database
# ---------------------------------------------------------

<<<<<<< HEAD
def is_mongodb_connected() -> bool:
    return _mongodb_connected
=======
def connect_db():
    """
    Test MongoDB connection.

    Returns:
        bool: True if connection succeeds.
    """

    try:

        client.admin.command(
            "ping"
        )

        print(
            "MongoDB connected successfully."
        )

        return True

    except ServerSelectionTimeoutError as e:

        print(
            "MongoDB connection failed:"
        )

        print(e)

        return False

    except PyMongoError as e:

        print(
            "MongoDB error:"
        )

        print(e)

        return False


# ---------------------------------------------------------
# Test Connection
# ---------------------------------------------------------

def test_connection():
    """
    Test the MongoDB connection.

    Returns:
        dict
    """

    try:

        client.admin.command(
            "ping"
        )

        return {
            "connected": True,
            "database": MONGO_DATABASE,
            "message":
                "MongoDB connection successful"
        }

    except Exception as e:

        return {
            "connected": False,
            "database": MONGO_DATABASE,
            "message": str(e)
        }


# ---------------------------------------------------------
# Close Connection
# ---------------------------------------------------------

def close_connection():
    """
    Close MongoDB client.
    """

    client.close()

    print(
        "MongoDB connection closed."
    )


# ---------------------------------------------------------
# Main Test
# ---------------------------------------------------------

if __name__ == "__main__":

    result = test_connection()

    print(result)

>>>>>>> fef0746 (Milestone 3)
