"""
Security recommendations based on risk factors.
"""


def generate_recommendations(event):
    """
    Generate recommendations based on detected risk factors.
    """

    recommendations = []

    risk_level = str(
        event.get("risk_level", "")
    ).lower()

    ioc_status = str(
        event.get("ioc_status", "")
    ).lower()

    event_type = str(
        event.get("event_type", "")
    ).lower()

    failed_logins = event.get(
        "failed_login_attempts",
        0
    )

    # Critical asset
    if str(
        event.get("asset_criticality", "")
    ).lower() == "critical":

        recommendations.append(
            "Investigate the affected critical asset immediately"
        )

    # Malicious IOC
    if ioc_status == "malicious":

        recommendations.append(
            "Investigate and block the malicious IOC"
        )

    # High CVSS
    try:
        cvss = float(
            event.get("cvss_score", 0)
        )

        if cvss >= 7:
            recommendations.append(
                "Review and remediate the high-risk vulnerability"
            )

    except (TypeError, ValueError):
        pass

    # Brute force / authentication attacks
    if (
        "brute" in event_type
        or "login" in event_type
    ):

        recommendations.append(
            "Review authentication logs"
        )

        recommendations.append(
            "Investigate the source IP and affected account"
        )

    # Failed login attempts
    try:
        if int(failed_logins) >= 10:

            recommendations.append(
                "Investigate repeated failed login attempts"
            )

    except (TypeError, ValueError):
        pass

    # After-hours activity
    if event.get("after_hours") is True:

        recommendations.append(
            "Review the after-hours activity"
        )

    # Critical risk
    if risk_level == "critical":

        recommendations.append(
            "Escalate the incident for immediate investigation"
        )

    elif risk_level == "high":

        recommendations.append(
            "Prioritize the event for security analyst review"
        )

    elif risk_level in ("medium", "moderate"):

        recommendations.append(
            "Continue monitoring the event"
        )

    else:

        recommendations.append(
            "Monitor the event for additional suspicious activity"
        )

    # Remove duplicate recommendations
    unique_recommendations = []

    for recommendation in recommendations:

        if recommendation not in unique_recommendations:
            unique_recommendations.append(
                recommendation
            )

    return unique_recommendations


def generate_recommendations_from_risk(
    risk_level,
    ioc_status=None,
    cvss_score=0
):
    """
    Generate basic recommendations when
    only risk information is available.
    """

    event = {
        "risk_level": risk_level,
        "ioc_status": ioc_status,
        "cvss_score": cvss_score
    }

    return generate_recommendations(event)