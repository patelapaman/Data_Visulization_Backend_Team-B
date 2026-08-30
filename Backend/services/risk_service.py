"""
Risk Service

Handles:
- Risk score calculation
- Risk level calculation
- Priority calculation
- Security recommendations
"""

from risk.risk_score import calculate_risk_assessment
from risk.prioritization import prioritize_incident
from risk.recommendations import generate_recommendations


def assess_risk(event):
    """
    Perform complete risk assessment for a security event.

    Parameters
    ----------
    event : dict
        Security event data.

    Returns
    -------
    dict
        Risk assessment result.
    """

    if not event:
        raise ValueError("Security event is required")

    # Calculate risk score and risk level
    risk = calculate_risk_assessment(event)

    # Add calculated values to event
    assessed_event = event.copy()
    assessed_event.update(risk)

    # Calculate priority
    priority = prioritize_incident(
        risk["risk_score"]
    )

    # Generate recommendations
    recommendations = generate_recommendations(
        assessed_event
    )

    return {
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "priority": priority["priority"],
        "recommended_action": priority[
            "recommended_action"
        ],
        "recommendations": recommendations
    }


def calculate_event_risk(event):
    """
    Calculate only the risk score and risk level.
    """

    if not event:
        raise ValueError("Event is required")

    return calculate_risk_assessment(event)


def get_event_priority(risk_score):
    """
    Calculate priority from a risk score.
    """

    return prioritize_incident(risk_score)


def get_event_recommendations(event):
    """
    Generate security recommendations for an event.
    """

    if not event:
        return []

    return generate_recommendations(event)


def process_events(events):
    """
    Calculate risk information for multiple events.

    Parameters
    ----------
    events : list
        List of security events.

    Returns
    -------
    list
        Assessed events.
    """

    results = []

    for event in events:

        try:
            assessment = assess_risk(event)

            processed_event = event.copy()
            processed_event.update(assessment)

            results.append(processed_event)

        except Exception as e:

            processed_event = event.copy()

            processed_event["risk_error"] = str(e)

            results.append(processed_event)

    return results