import pandas as pd


def check_security_rules(event):
    """
    Apply security rules to a single security event.

    Returns
    -------
    dict
        Rule results and reasons.
    """

    if isinstance(event, pd.Series):
        event = event.to_dict()

    triggered_rules = []
    risk_points = 0

    # --------------------------------------------------
    # Rule 1: Multiple failed login attempts
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

        triggered_rules.append(
            "Multiple failed login attempts detected"
        )

        risk_points += 25

    elif failed_logins >= 5:

        triggered_rules.append(
            "Elevated failed login attempts detected"
        )

        risk_points += 15

    # --------------------------------------------------
    # Rule 2: Malware detected
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

        triggered_rules.append(
            "Malware detected"
        )

        risk_points += 30

    # --------------------------------------------------
    # Rule 3: Impossible travel
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

        triggered_rules.append(
            "Impossible travel detected"
        )

        risk_points += 25

    # --------------------------------------------------
    # Rule 4: After-hours activity
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

        triggered_rules.append(
            "Suspicious after-hours activity"
        )

        risk_points += 10

    # --------------------------------------------------
    # Rule 5: High CVSS score
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

        triggered_rules.append(
            "Critical vulnerability detected"
        )

        risk_points += 25

    elif cvss >= 7:

        triggered_rules.append(
            "High severity vulnerability detected"
        )

        risk_points += 15

    # --------------------------------------------------
    # Rule 6: High threat score
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

        triggered_rules.append(
            "Critical threat score detected"
        )

        risk_points += 25

    elif threat_score >= 70:

        triggered_rules.append(
            "High threat score detected"
        )

        risk_points += 15

    # --------------------------------------------------
    # Limit score to 100
    # --------------------------------------------------

    risk_points = min(
        risk_points,
        100
    )

    # --------------------------------------------------
    # Determine rule-based result
    # --------------------------------------------------

    if risk_points >= 70:
        rule_risk = "High"

    elif risk_points >= 40:
        rule_risk = "Medium"

    elif risk_points > 0:
        rule_risk = "Low"

    else:
        rule_risk = "Normal"

    return {
        "rule_risk": rule_risk,
        "rule_score": risk_points,
        "triggered_rules": triggered_rules
    }


def apply_rules(df):
    """
    Apply security rules to every event.
    """

    if df is None or df.empty:
        raise ValueError(
            "Input dataframe is empty."
        )

    result = df.copy()

    rule_results = result.apply(
        check_security_rules,
        axis=1
    )

    result["rule_risk"] = rule_results.apply(
        lambda x: x["rule_risk"]
    )

    result["rule_score"] = rule_results.apply(
        lambda x: x["rule_score"]
    )

    result["triggered_rules"] = rule_results.apply(
        lambda x: x["triggered_rules"]
    )

    print(
        "Security rules applied successfully."
    )

    return result


if __name__ == "__main__":

    sample_event = {
        "failed_login_attempts": 15,
        "malware_detected": True,
        "impossible_travel_flag": True,
        "after_hours_activity": True,
        "cvss_score": 9.5,
        "threat_score": 90
    }

    result = check_security_rules(
        sample_event
    )

    print(result)