WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 80,
    "MEDIUM": 60,
    "LOW": 30,
    "INFO": 0,
    "ERROR": 0
}


def rank(findings):

    result = []

    for original in findings:

        finding = dict(original)

        severity = str(
            finding.get("severity", "INFO")
        ).upper()

        if severity not in WEIGHTS:
            severity = "INFO"

        finding["severity"] = severity
        finding["risk_score"] = WEIGHTS[severity]

        result.append(finding)

    return sorted(
        result,
        key=lambda item: item["risk_score"],
        reverse=True
    )
