"""
Risk score calculation.

Risk Score =
    Threat Severity      × 0.25
    + ML Confidence      × 0.25
    + Asset Criticality  × 0.20
    + Vulnerability Risk × 0.20
    + Threat Intelligence× 0.10
"""


def normalize_threat_severity(severity):
    """Convert threat severity to a 0-100 score."""

    if severity is None:
        return 0

    if isinstance(severity, (int, float)):
        return max(0, min(100, float(severity)))

    mapping = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "moderate": 50,
        "low": 25
    }

    return mapping.get(str(severity).lower(), 0)


def normalize_asset_criticality(criticality):
    """Convert asset criticality to a 0-100 score."""

    if criticality is None:
        return 0

    if isinstance(criticality, (int, float)):
        return max(0, min(100, float(criticality)))

    mapping = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25
    }

    return mapping.get(str(criticality).lower(), 0)


def normalize_cvss(cvss_score):
    """Convert CVSS score from 0-10 to 0-100."""

    try:
        score = float(cvss_score)
        return max(0, min(100, score * 10))
    except (TypeError, ValueError):
        return 0


def normalize_ml_confidence(confidence):
    """Convert ML confidence into a 0-100 score."""

    try:
        confidence = float(confidence)

        # Accept either 0-1 or 0-100 format
        if 0 <= confidence <= 1:
            confidence *= 100

        return max(0, min(100, confidence))

    except (TypeError, ValueError):
        return 0


def calculate_vulnerability_risk(cvss_score):
    """Calculate vulnerability risk from CVSS."""

    return normalize_cvss(cvss_score)


def calculate_threat_intelligence_score(ioc_status):
    """
    Convert IOC status into a threat intelligence score.
    """

    if ioc_status is None:
        return 0

    mapping = {
        "malicious": 100,
        "suspicious": 75,
        "unknown": 25,
        "clean": 0,
        "benign": 0
    }

    return mapping.get(str(ioc_status).lower(), 0)


def calculate_risk_score(
    threat_severity,
    ml_confidence,
    asset_criticality,
    cvss_score,
    ioc_status
):
    """
    Calculate final risk score from 0-100.

    Weights:
        Threat Severity      = 25%
        ML Confidence        = 25%
        Asset Criticality    = 20%
        Vulnerability Risk   = 20%
        Threat Intelligence  = 10%
    """

    severity_score = normalize_threat_severity(
        threat_severity
    )

    ml_score = normalize_ml_confidence(
        ml_confidence
    )

    asset_score = normalize_asset_criticality(
        asset_criticality
    )

    vulnerability_score = calculate_vulnerability_risk(
        cvss_score
    )

    intelligence_score = calculate_threat_intelligence_score(
        ioc_status
    )

    risk_score = (
        (severity_score * 0.25) +
        (ml_score * 0.25) +
        (asset_score * 0.20) +
        (vulnerability_score * 0.20) +
        (intelligence_score * 0.10)
    )

    return round(max(0, min(100, risk_score)), 2)


def get_risk_level(risk_score):
    """
    Convert risk score into risk category.

    0-20   -> Low
    21-40  -> Medium
    41-60  -> Moderate
    61-80  -> High
    81-100 -> Critical
    """

    score = float(risk_score)

    if score <= 20:
        return "Low"

    elif score <= 40:
        return "Medium"

    elif score <= 60:
        return "Moderate"

    elif score <= 80:
        return "High"

    return "Critical"


def calculate_risk_assessment(event):
    """
    Calculate complete risk assessment for an event.
    """

    risk_score = calculate_risk_score(
        threat_severity=event.get("severity"),
        ml_confidence=event.get("ml_confidence", 0),
        asset_criticality=event.get("asset_criticality"),
        cvss_score=event.get("cvss_score", 0),
        ioc_status=event.get("ioc_status")
    )

    risk_level = get_risk_level(risk_score)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level
    }