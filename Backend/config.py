import os
from dotenv import load_dotenv

from pathlib import Path

# Load environment variables from Backend/.env when running locally. Production
# environments should provide these values through their secret manager.
load_dotenv(Path(__file__).resolve().parent / ".env")

class Config:
    """
    Application Configuration
    """

    # Flask Settings
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")

    # MongoDB Settings
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")

    DATABASE_NAME = os.getenv("DATABASE_NAME", "ThreatDetectionDB")

    # Debug Mode
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

    # API and operational settings
    API_TITLE = "AI-Assisted Threat Detection Dashboard"
    API_VERSION = os.getenv("API_VERSION", "2.0.0")
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
    LOG_FILE = os.getenv(
        "LOG_FILE",
        str(Path(__file__).resolve().parent / "logs" / "application.log"),
    )
    EXPORT_FOLDER = os.getenv(
        "EXPORT_FOLDER",
        str(Path(__file__).resolve().parent / "outputs"),
    )
    MAX_PAGE_SIZE = int(os.getenv("MAX_PAGE_SIZE", "500"))
    MONGO_SERVER_SELECTION_TIMEOUT_MS = int(
        os.getenv("MONGO_SERVER_SELECTION_TIMEOUT_MS", "3000")
    )
    MONGO_CONNECT_TIMEOUT_MS = int(
        os.getenv("MONGO_CONNECT_TIMEOUT_MS", "3000")
    )

    # Upload Folder (Optional)
    UPLOAD_FOLDER = "data"

    # Allowed File Extensions
    ALLOWED_EXTENSIONS = {"csv"}

    # Maximum Upload Size (16 MB)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024