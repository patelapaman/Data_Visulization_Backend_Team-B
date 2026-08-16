import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


def evaluate_classifier(
    y_true,
    y_pred
):
    """
    Evaluate a classification model.

    Parameters
    ----------
    y_true : array-like
        Actual labels.

    y_pred : array-like
        Predicted labels.

    Returns
    -------
    dict
        Evaluation metrics.
    """

    if len(y_true) == 0:
        raise ValueError(
            "Actual labels are empty."
        )

    if len(y_pred) == 0:
        raise ValueError(
            "Predicted labels are empty."
        )

    # --------------------------------------------------
    # Calculate metrics
    # --------------------------------------------------

    accuracy = accuracy_score(
        y_true,
        y_pred
    )

    precision = precision_score(
        y_true,
        y_pred,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        y_true,
        y_pred,
        average="weighted",
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        y_pred,
        average="weighted",
        zero_division=0
    )

    matrix = confusion_matrix(
        y_true,
        y_pred
    )

    report = classification_report(
        y_true,
        y_pred,
        zero_division=0
    )

    results = {
        "accuracy": round(
            accuracy,
            4
        ),

        "precision": round(
            precision,
            4
        ),

        "recall": round(
            recall,
            4
        ),

        "f1_score": round(
            f1,
            4
        ),

        "confusion_matrix": matrix.tolist(),

        "classification_report": report
    }

    return results


def print_evaluation(results):
    """
    Print model evaluation results.
    """

    print("\n")
    print("=" * 50)
    print("MODEL EVALUATION")
    print("=" * 50)

    print(
        f"Accuracy  : "
        f"{results['accuracy']:.4f}"
    )

    print(
        f"Precision : "
        f"{results['precision']:.4f}"
    )

    print(
        f"Recall    : "
        f"{results['recall']:.4f}"
    )

    print(
        f"F1 Score  : "
        f"{results['f1_score']:.4f}"
    )

    print("\nConfusion Matrix:")

    for row in results[
        "confusion_matrix"
    ]:

        print(row)

    print("\nClassification Report:")

    print(
        results[
            "classification_report"
        ]
    )

    print("=" * 50)


def compare_models(model_results):
    """
    Compare multiple ML models.

    Parameters
    ----------
    model_results : dict

        Example:

        {
            "Random Forest": {
                "accuracy": 0.91,
                "precision": 0.90,
                "recall": 0.89,
                "f1_score": 0.895
            },

            "Logistic Regression": {
                ...
            }
        }

    Returns
    -------
    pandas.DataFrame
    """

    if not model_results:
        raise ValueError(
            "No model results provided."
        )

    rows = []

    for model_name, metrics in (
        model_results.items()
    ):

        rows.append(
            {
                "model": model_name,
                "accuracy": metrics.get(
                    "accuracy",
                    0
                ),
                "precision": metrics.get(
                    "precision",
                    0
                ),
                "recall": metrics.get(
                    "recall",
                    0
                ),
                "f1_score": metrics.get(
                    "f1_score",
                    0
                )
            }
        )

    comparison = pd.DataFrame(
        rows
    )

    return comparison.sort_values(
        by="f1_score",
        ascending=False
    )


if __name__ == "__main__":

    # Example values
    actual = [
        "Normal",
        "Normal",
        "Suspicious",
        "Suspicious",
        "Malicious",
        "Malicious"
    ]

    predicted = [
        "Normal",
        "Suspicious",
        "Suspicious",
        "Suspicious",
        "Malicious",
        "Normal"
    ]

    results = evaluate_classifier(
        actual,
        predicted
    )

    print_evaluation(
        results
    )