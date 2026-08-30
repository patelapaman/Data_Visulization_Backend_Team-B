"""
Prediction Repository

Handles storing and retrieving ML predictions
from MongoDB.
"""

from datetime import datetime
from database.mongodb import get_database


class PredictionRepository:

    def __init__(self, collection_name="predictions"):
        self.db = get_database()
        self.collection = self.db[collection_name]

    def create_prediction(self, prediction):
        """
        Store a prediction in MongoDB.
        """

        if not prediction:
            raise ValueError("Prediction data is required")

        prediction = prediction.copy()

        prediction["created_at"] = datetime.utcnow()

        result = self.collection.insert_one(
            prediction
        )

        return str(result.inserted_id)

    def get_prediction(self, prediction_id):
        """
        Retrieve a prediction by MongoDB ID.
        """

        from bson import ObjectId

        try:
            object_id = ObjectId(prediction_id)
        except Exception:
            return None

        prediction = self.collection.find_one(
            {"_id": object_id}
        )

        if prediction:
            prediction["_id"] = str(
                prediction["_id"]
            )

        return prediction

    def get_predictions(
        self,
        limit=100
    ):
        """
        Retrieve recent predictions.
        """

        predictions = list(
            self.collection.find(
                {},
                {"_id": 0}
            )
            .sort("created_at", -1)
            .limit(limit)
        )

        return predictions

    def get_predictions_by_event(
        self,
        event_id
    ):
        """
        Retrieve predictions associated
        with a security event.
        """

        predictions = list(
            self.collection.find(
                {
                    "event_id": event_id
                },
                {
                    "_id": 0
                }
            )
        )

        return predictions

    def update_prediction(
        self,
        prediction_id,
        update_data
    ):
        """
        Update a prediction.
        """

        from bson import ObjectId

        try:
            object_id = ObjectId(prediction_id)
        except Exception:
            return None

        update_data = update_data.copy()

        update_data["updated_at"] = datetime.utcnow()

        result = self.collection.update_one(
            {
                "_id": object_id
            },
            {
                "$set": update_data
            }
        )

        if result.matched_count == 0:
            return None

        return self.get_prediction(
            prediction_id
        )

    def delete_prediction(
        self,
        prediction_id
    ):
        """
        Delete a prediction.
        """

        from bson import ObjectId

        try:
            object_id = ObjectId(prediction_id)
        except Exception:
            return False

        result = self.collection.delete_one(
            {
                "_id": object_id
            }
        )

        return result.deleted_count > 0