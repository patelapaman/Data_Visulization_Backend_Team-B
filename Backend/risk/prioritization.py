"""
Incident priority calculation.
"""


def calculate_priority(risk_score):
    """
    Convert risk score into investigation priority.
    """

    score = float(risk_score)

    if score >= 81:
        return "Immediate"

    elif score >= 61:
        return "High"

    elif score >= 41:
        return "Medium"

    return "Low"


def calculate_priority_from_level(risk_level):
    """
    Calculate priority using risk level.
    """

    if not risk_level:
        return "Low"

    mapping = {
        "critical": "Immediate",
        "high": "High",
        "moderate": "Medium",
        "medium": "Medium",
        "low": "Low"
    }

    return mapping.get(
        str(risk_level).lower(),
        "Low"
    )


def prioritize_incident(risk_score):
    """
    Return complete priority information.
    """

    priority = calculate_priority(risk_score)

    if priority == "Immediate":
        action = "Immediate Investigation"

    elif priority == "High":
        action = "Investigate as soon as possible"

    elif priority == "Medium":
        action = "Review and monitor"

    else:
        action = "Monitor"

    return {
        "priority": priority,
        "recommended_action": action
    }