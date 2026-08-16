import os
import json
import joblib


# ---------------------------------------------------------
# Model directory
# ---------------------------------------------------------

MODEL_FOLDER = "trained_models"


def create_model_folder():
    """
    Create trained_models directory
    if it does not exist.
    """

    os.makedirs(
        MODEL_FOLDER,
        exist_ok=True
    )


# ---------------------------------------------------------
# Save model
# ---------------------------------------------------------

def save_model(
    model,
    filename
):
    """
    Save a trained ML model.

    Example:
        save_model(
            detector.model,
            "isolation_forest_v1.pkl"
        )
    """

    create_model_folder()

    path = os.path.join(
        MODEL_FOLDER,
        filename
    )

    joblib.dump(
        model,
        path
    )

    print(
        f"Model saved successfully: {path}"
    )

    return path


# ---------------------------------------------------------
# Load model
# ---------------------------------------------------------

def load_model(filename):
    """
    Load a previously saved ML model.
    """

    path = os.path.join(
        MODEL_FOLDER,
        filename
    )

    if not os.path.exists(path):

        raise FileNotFoundError(
            f"Model not found: {path}"
        )

    model = joblib.load(
        path
    )

    print(
        f"Model loaded successfully: {path}"
    )

    return model


# ---------------------------------------------------------
# Save model metadata
# ---------------------------------------------------------

def save_metadata(
    metadata,
    filename="metadata.json"
):
    """
    Save information about trained models.

    Example metadata:

    {
        "model_version": "IF_v1",
        "algorithm": "Isolation Forest",
        "features": [...]
    }
    """

    create_model_folder()

    path = os.path.join(
        MODEL_FOLDER,
        filename
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            metadata,
            file,
            indent=4
        )

    print(
        f"Model metadata saved: {path}"
    )

    return path


# ---------------------------------------------------------
# Load metadata
# ---------------------------------------------------------

def load_metadata(
    filename="metadata.json"
):
    """
    Load model metadata.
    """

    path = os.path.join(
        MODEL_FOLDER,
        filename
    )

    if not os.path.exists(path):

        raise FileNotFoundError(
            f"Metadata not found: {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        metadata = json.load(
            file
        )

    return metadata


# ---------------------------------------------------------
# Check whether model exists
# ---------------------------------------------------------

def model_exists(filename):
    """
    Check whether a saved model exists.
    """

    path = os.path.join(
        MODEL_FOLDER,
        filename
    )

    return os.path.exists(path)


# ---------------------------------------------------------
# Example usage
# ---------------------------------------------------------

if __name__ == "__main__":

    create_model_folder()

    print(
        f"Model folder ready: {MODEL_FOLDER}"
    )
