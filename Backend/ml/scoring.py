import pandas as pd


# ---------------------------------------------------------
# Risk Level Calculation
# ---------------------------------------------------------

def calculate_risk_level(score):
    """
    Convert a numerical score into a risk level.

    Score:
        90-100 -> Critical
        70-89  -> High
        40-69  -> Medium
        0-39   -> Low
    """

    if score >= 90:
        return "Critical"

    elif score >= 70:
        return "High"

    elif score >= 40:
        return "Medium"

    else:
        return "Low"


# ---------------------------------------------------------
# Normalize value between 0 and 100
# ---------------------------------------------------------

def normalize_score(value):
    """
    Convert a value to a 0-100 range.
    """

    try:
        value = float(value)
    except (ValueError, TypeError):
        return 0.0

    return max(0.0, min(100.0, value))


# ---------------------------------------------------------
# Calculate Threat Confidence Score
# ---------------------------------------------------------

def calculate_confidence_score(
    anomaly_score=0,
    threat_score=0,
    severity_score=0,
    failed_login_attempts=0,
    malware_detected=False,
    impossible_travel_flag=False,
    after_hours_activity=False
):
    """
    Calculate an overall threat confidence score.

    The score combines:

    - Anomaly detection
    - Existing threat score
    - Severity
    - Failed login attempts
    - Malware detection
    - Impossible travel
    - After-hours activity

    Returns
    -------
    float
        Confidence score between 0 and 100.
    """

    # -----------------------------------------------------
    # Normalize existing scores
    # -----------------------------------------------------

    threat_score = normalize_score(
        threat_score
    )

    severity_score = normalize_score(
        severity_score
    )

    # -----------------------------------------------------
    # Convert Isolation Forest score
    #
    # Isolation Forest:
    # Higher score  -> more normal
    # Lower score   -> more anomalous
    #
    # We convert it so that:
    # Higher value -> more suspicious
    # -----------------------------------------------------

    try:
        anomaly_score = float(anomaly_score)
    except (ValueError, TypeError):
        anomaly_score = 0

    anomaly_score = max(
        -1,
        min(1, anomaly_score)
    )

    anomaly_risk = (
        (1 - anomaly_score) / 2
    ) * 100

    # -----------------------------------------------------
    # Failed login risk
    # -----------------------------------------------------

    try:
        failed_login_attempts = int(
            failed_login_attempts
        )
    except (ValueError, TypeError):
        failed_login_attempts = 0

    failed_login_risk = min(
        failed_login_attempts * 5,
        100
    )

    # -----------------------------------------------------
    # Malware risk
    # -----------------------------------------------------

    malware_risk = 100 if (
        malware_detected is True
        or str(malware_detected).lower()
        in ["true", "yes", "1"]
    ) else 0

    # -----------------------------------------------------
    # Impossible travel risk
    # -----------------------------------------------------

    travel_risk = 100 if (
        impossible_travel_flag is True
        or str(impossible_travel_flag).lower()
        in ["true", "yes", "1"]
    ) else 0

    # -----------------------------------------------------
    # After-hours activity
    # -----------------------------------------------------

    after_hours_risk = 100 if (
        after_hours_activity is True
        or str(after_hours_activity).lower()
        in ["true", "yes", "1"]
    ) else 0

    # -----------------------------------------------------
    # Weighted score
    # -----------------------------------------------------

    confidence = (
        anomaly_risk * 0.25
        + threat_score * 0.25
        + severity_score * 0.15
        + failed_login_risk * 0.10
        + malware_risk * 0.10
        + travel_risk * 0.05
        + after_hours_risk * 0.10
    )

    return round(
        normalize_score(confidence),
        2
    )


# ---------------------------------------------------------
# Calculate score for a single security event
# ---------------------------------------------------------

def score_event(event):
    """
    Calculate threat confidence and risk level
    for one security event.

    Parameters
    ----------
    event : dict or pandas.Series

    Returns
    -------
    dict
    """

    if isinstance(event, pd.Series):
        event = event.to_dict()

    confidence_score = calculate_confidence_score(
        anomaly_score=event.get(
            "anomaly_score",
            0
        ),

        threat_score=event.get(
            "threat_score",
            0
        ),

        severity_score=event.get(
            "severity_score",
            0
        ),

        failed_login_attempts=event.get(
            "failed_login_attempts",
            0
        ),

        malware_detected=event.get(
            "malware_detected",
            False
        ),

        impossible_travel_flag=event.get(
            "impossible_travel_flag",
            False
        ),

        after_hours_activity=event.get(
            "after_hours_activity",
            False
        )
    )

    risk_level = calculate_risk_level(
        confidence_score
    )

    # -----------------------------------------------------
    # Determine prediction
    # -----------------------------------------------------

    anomaly_status = str(
        event.get(
            "anomaly_status",
            ""
        )
    ).lower()

    if (
        anomaly_status == "suspicious"
        or confidence_score >= 70
    ):
        prediction = "Suspicious"
    else:
        prediction = "Normal"

    return {
        "prediction": prediction,
        "confidence_score": confidence_score,
        "risk_level": risk_level
    }


# ---------------------------------------------------------
# Score complete dataframe
# ---------------------------------------------------------

def score_dataframe(df):
    """
    Calculate threat scores for all security events.

    Parameters
    ----------
    df : pandas.DataFrame

    Returns
    -------
    pandas.DataFrame
    """

    if df is None or df.empty:
        raise ValueError(
            "Input dataframe is empty."
        )

    result = df.copy()

    # -----------------------------------------------------
    # Calculate score for every row
    # -----------------------------------------------------

    scores = result.apply(
        score_event,
        axis=1
    )

    # -----------------------------------------------------
    # Add results to dataframe
    # -----------------------------------------------------

    result["prediction"] = scores.apply(
        lambda x: x["prediction"]
    )

    result["confidence_score"] = scores.apply(
        lambda x: x["confidence_score"]
    )

    result["risk_level"] = scores.apply(
        lambda x: x["risk_level"]
    )

    print(
        "\nThreat scoring completed successfully."
    )

    print(
        f"Processed events: {len(result)}"
    )

    return result


# ---------------------------------------------------------
# Example usage
# ---------------------------------------------------------

if __name__ == "__main__":

    sample_data = pd.DataFrame(
        [
            {
                "event_id": "EVT001",
                "anomaly_score": -0.75,
                "threat_score": 90,
                "severity_score": 90,
                "failed_login_attempts": 15,
                "malware_detected": True,
                "impossible_travel_flag": True,
                "after_hours_activity": True,
                "anomaly_status": "Suspicious"
            },
            {
                "event_id": "EVT002",
                "anomaly_score": 0.60,
                "threat_score": 20,
                "severity_score": 20,
                "failed_login_attempts": 1,
                "malware_detected": False,
                "impossible_travel_flag": False,
                "after_hours_activity": False,
                "anomaly_status": "Normal"
            }
        ]
    )

    scored_data = score_dataframe(
        sample_data
    )

    print("\nScored Data:")
    print(scored_data)