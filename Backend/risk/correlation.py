"""
Security event correlation.

Events can be correlated using:
1. Same user
2. Same source IP
3. Same asset
4. MITRE ATT&CK sequence
5. Short time window
"""

from datetime import datetime


MITRE_SEQUENCE = [
    "initial access",
    "credential access",
    "privilege escalation",
    "lateral movement",
    "exfiltration"
]


def parse_timestamp(timestamp):
    """Convert timestamp into datetime."""

    if isinstance(timestamp, datetime):
        return timestamp

    if not timestamp:
        return None

    try:
        return datetime.fromisoformat(
            str(timestamp).replace("Z", "+00:00")
        )
    except (ValueError, TypeError):
        return None


def same_time_window(event1, event2, minutes=30):
    """Check whether two events occurred within the time window."""

    time1 = parse_timestamp(event1.get("timestamp"))
    time2 = parse_timestamp(event2.get("timestamp"))

    if not time1 or not time2:
        return False

    difference = abs(
        (time1 - time2).total_seconds()
    )

    return difference <= minutes * 60


def same_user(event1, event2):
    """Check whether two events involve the same user."""

    user1 = event1.get("user_id")
    user2 = event2.get("user_id")

    return bool(
        user1 and user2 and user1 == user2
    )


def same_source_ip(event1, event2):
    """Check whether two events have the same source IP."""

    ip1 = event1.get("source_ip")
    ip2 = event2.get("source_ip")

    return bool(
        ip1 and ip2 and ip1 == ip2
    )


def same_asset(event1, event2):
    """Check whether two events affect the same asset."""

    asset1 = event1.get("asset_id")
    asset2 = event2.get("asset_id")

    return bool(
        asset1 and asset2 and asset1 == asset2
    )


def same_mitre_technique(event1, event2):
    """Check whether two events use the same MITRE technique."""

    technique1 = event1.get("mitre_technique")
    technique2 = event2.get("mitre_technique")

    return bool(
        technique1 and
        technique2 and
        technique1 == technique2
    )


def get_correlation_reasons(event1, event2):
    """
    Return reasons explaining why two events are related.
    """

    reasons = []

    if same_user(event1, event2):
        reasons.append("Same user")

    if same_source_ip(event1, event2):
        reasons.append("Same source IP")

    if same_asset(event1, event2):
        reasons.append("Same asset")

    if same_mitre_technique(event1, event2):
        reasons.append("Same MITRE technique")

    if same_time_window(event1, event2):
        reasons.append("Short time window")

    return reasons


def are_events_related(event1, event2):
    """
    Determine whether two security events are related.
    """

    reasons = get_correlation_reasons(
        event1,
        event2
    )

    return len(reasons) > 0


def correlate_events(events, time_window_minutes=30):
    """
    Group related security events.

    Returns a list of attack groups.
    """

    if not events:
        return []

    groups = []

    for event in events:

        placed = False

        for group in groups:

            for existing_event in group:

                related = (
                    same_user(event, existing_event)
                    or same_source_ip(event, existing_event)
                    or same_asset(event, existing_event)
                    or same_mitre_technique(
                        event,
                        existing_event
                    )
                )

                time_match = same_time_window(
                    event,
                    existing_event,
                    time_window_minutes
                )

                if related and time_match:

                    group.append(event)
                    placed = True
                    break

            if placed:
                break

        if not placed:
            groups.append([event])

    return groups


def detect_attack_chain(events):
    """
    Detect a possible MITRE-style attack chain.
    """

    stages_found = []

    for event in events:

        technique = str(
            event.get("mitre_tactic", "")
        ).lower()

        if technique in MITRE_SEQUENCE:
            stages_found.append(technique)

    unique_stages = []

    for stage in MITRE_SEQUENCE:
        if stage in stages_found:
            unique_stages.append(stage)

    return unique_stages


def create_attack_chain(events):
    """
    Create a readable attack-chain representation.
    """

    stages = detect_attack_chain(events)

    if not stages:
        return []

    return stages