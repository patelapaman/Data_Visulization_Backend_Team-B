import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DATABASE = os.getenv("MONGO_DATABASE", "threat_detection")

if not MONGO_URI:
    raise ValueError("MONGO_URI is not set in the .env file")

# Create MongoDB client
client = MongoClient(MONGO_URI)

# Select database
db = client[MONGO_DATABASE]


def get_database():
    """Return the MongoDB database."""
    return db


def get_db():
    """Backward-compatible alias."""
    return db


def connect_db():
    """Test MongoDB connection."""
    try:
        client.admin.command("ping")
        print("MongoDB connected successfully!")
        return db
    except Exception as e:
        print(f"MongoDB connection failed: {e}")
        return None


def test_connection():
    """Test whether MongoDB is reachable."""
    try:
        client.admin.command("ping")
        return True
    except Exception as e:
        print(f"MongoDB connection failed: {e}")
        return False