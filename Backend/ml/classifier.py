import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)


class ThreatClassifier:
    """
    Random Forest based threat classifier.

    Expected target examples:

    Normal
    Suspicious
    Malicious

    or:

    0 = Normal
    1 = Suspicious
    2 = Malicious
    """

    def __init__(
        self,
        n_estimators=200,
        random_state=42
    ):

        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=random_state,
            class_weight="balanced",
            n_jobs=-1
        )

        self.is_trained = False

    # --------------------------------------------------
    # Train classifier
    # --------------------------------------------------

    def train(
        self,
        X,
        y,
        test_size=0.2
    ):
        """
        Train Random Forest classifier.
        """

        if X is None or len(X) == 0:
            raise ValueError(
                "Training features are empty."
            )

        if y is None or len(y) == 0:
            raise ValueError(
                "Training labels are empty."
            )

        # --------------------------------------------------
        # Check number of classes
        # --------------------------------------------------

        if len(pd.Series(y).unique()) < 2:
            raise ValueError(
                "Classifier requires at least "
                "two different classes."
            )

        # --------------------------------------------------
        # Split dataset
        # --------------------------------------------------

        X_train, X_test, y_train, y_test = (
            train_test_split(
                X,
                y,
                test_size=test_size,
                random_state=42,
                stratify=y
            )
        )

        # --------------------------------------------------
        # Train
        # --------------------------------------------------

        self.model.fit(
            X_train,
            y_train
        )

        self.is_trained = True

        # --------------------------------------------------
        # Evaluate
        # --------------------------------------------------

        predictions = self.model.predict(
            X_test
        )

        metrics = {
            "accuracy": accuracy_score(
                y_test,
                predictions
            ),

            "precision": precision_score(
                y_test,
                predictions,
                average="weighted",
                zero_division=0
            ),

            "recall": recall_score(
                y_test,
                predictions,
                average="weighted",
                zero_division=0
            ),

            "f1_score": f1_score(
                y_test,
                predictions,
                average="weighted",
                zero_division=0
            )
        }

        print("\nThreat Classifier Performance")
        print("--------------------------------")

        print(
            f"Accuracy  : {metrics['accuracy']:.4f}"
        )

        print(
            f"Precision : {metrics['precision']:.4f}"
        )

        print(
            f"Recall    : {metrics['recall']:.4f}"
        )

        print(
            f"F1 Score  : {metrics['f1_score']:.4f}"
        )

        print("\nClassification Report:")
        print(
            classification_report(
                y_test,
                predictions,
                zero_division=0
            )
        )

        return metrics

    # --------------------------------------------------
    # Predict threat class
    # --------------------------------------------------

    def predict(self, X):
        """
        Predict threat class.
        """

        if not self.is_trained:
            raise RuntimeError(
                "Classifier has not been trained."
            )

        return self.model.predict(X)

    # --------------------------------------------------
    # Predict probabilities
    # --------------------------------------------------

    def predict_probability(self, X):
        """
        Return class probabilities.
        """

        if not self.is_trained:
            raise RuntimeError(
                "Classifier has not been trained."
            )

        return self.model.predict_proba(X)

    # --------------------------------------------------
    # Get confidence score
    # --------------------------------------------------

    def confidence_score(self, X):
        """
        Return the highest class probability
        as a percentage.
        """

        probabilities = self.predict_probability(X)

        confidence = probabilities.max(
            axis=1
        ) * 100

        return confidence

    # --------------------------------------------------
    # Feature importance
    # --------------------------------------------------

    def feature_importance(
        self,
        feature_names
    ):
        """
        Return feature importance values.
        """

        if not self.is_trained:
            raise RuntimeError(
                "Classifier has not been trained."
            )

        importance = (
            self.model.feature_importances_
        )

        result = pd.DataFrame(
            {
                "feature": feature_names,
                "importance": importance
            }
        )

        return result.sort_values(
            by="importance",
            ascending=False
        )