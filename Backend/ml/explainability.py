import pandas as pd


def explain_event(event):
    """
    Generate a human-readable explanation
    for a security event.
    """

    if isinstance(event, pd.Series):
        event = event.to_dict()

    reasons = []

    # --------------------------------------------------
    # Failed login attempts
    # --------------------------------------------------

    failed_logins = event.get(
        "failed_login_attempts",
        0
    )

    try:
        failed_logins = int(failed_logins)
    except (ValueError, TypeError):
        failed_logins = 0

    if failed_logins >= 10:

        reasons.append(
            f"{failed_logins} failed login attempts detected"
        )

    elif failed_logins >= 5:

        reasons.append(
            f"Elevated failed login attempts: "
            f"{failed_logins}"
        )

    # --------------------------------------------------
    # Malware
    # --------------------------------------------------

    malware = event.get(
        "malware_detected",
        False
    )

    if str(malware).lower() in [
        "true",
        "yes",
        "1"
    ]:

        reasons.append(
            "Malware detected"
        )

    # --------------------------------------------------
    # Impossible travel
    # --------------------------------------------------

    impossible_travel = event.get(
        "impossible_travel_flag",
        False
    )

    if str(impossible_travel).lower() in [
        "true",
        "yes",
        "1"
    ]:

        reasons.append(
            "Impossible travel detected"
        )

    # --------------------------------------------------
    # After-hours activity
    # --------------------------------------------------

    after_hours = event.get(
        "after_hours_activity",
        False
    )

    if str(after_hours).lower() in [
        "true",
        "yes",
        "1"
    ]:

        reasons.append(
            "Suspicious after-hours activity"
        )

    # --------------------------------------------------
    # CVSS
    # --------------------------------------------------

    cvss = event.get(
        "cvss_score",
        0
    )

    try:
        cvss = float(cvss)
    except (ValueError, TypeError):
        cvss = 0

    if cvss >= 9:

        reasons.append(
            f"Critical vulnerability severity "
            f"(CVSS {cvss})"
        )

    elif cvss >= 7:

        reasons.append(
            f"High vulnerability severity "
            f"(CVSS {cvss})"
        )

    # --------------------------------------------------
    # Threat score
    # --------------------------------------------------

    threat_score = event.get(
        "threat_score",
        0
    )

    try:
        threat_score = float(threat_score)
    except (ValueError, TypeError):
        threat_score = 0

    if threat_score >= 90:

        reasons.append(
            "Critical threat score"
        )

    elif threat_score >= 70:

        reasons.append(
            "High threat score"
        )

    # --------------------------------------------------
    # Anomaly detection
    # --------------------------------------------------

    anomaly_status = str(
        event.get(
            "anomaly_status",
            ""
        )
    ).lower()

    if anomaly_status == "suspicious":

        reasons.append(
            "Machine learning model detected "
            "anomalous behavior"
        )

    # --------------------------------------------------
    # Default explanation
    # --------------------------------------------------

    if not reasons:

        reasons.append(
            "No major suspicious indicators detected"
        )

    return reasons


def generate_explanation(event):
    """
    Generate a complete explanation object.
    """

    if isinstance(event, pd.Series):
        event = event.to_dict()

    reasons = explain_event(event)

    prediction = event.get(
        "prediction",
        "Unknown"
    )

    confidence = event.get(
        "confidence_score",
        0
    )

    risk_level = event.get(
        "risk_level",
        "Unknown"
    )

    return {
        "prediction": prediction,
        "confidence_score": confidence,
        "risk_level": risk_level,
        "reasons": reasons
    }


def explain_dataframe(df):
    """
    Generate explanations for all events.
    """

    if df is None or df.empty:
        raise ValueError(
            "Input dataframe is empty."
        )

    result = df.copy()

    result["explanation"] = result.apply(
        explain_event,
        axis=1
    )

    return result


if __name__ == "__main__":

    sample_event = {
        "prediction": "Suspicious",
        "confidence_score": 91,
        "risk_level": "Critical",
        "failed_login_attempts": 15,
        "malware_detected": True,
        "impossible_travel_flag": True,
        "after_hours_activity": True,
        "cvss_score": 9.5,
        "threat_score": 90,
        "anomaly_status": "Suspicious"
    }

    explanation = generate_explanation(
        sample_event
    )

    print("\nThreat Explanation:")
    print(explanation)