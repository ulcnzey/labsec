import sqlite3


DATABASE_PATH = "database/labsec.db"


def get_connection():
    """
    Creates a connection to the LabSec database.
    """
    return sqlite3.connect(DATABASE_PATH)


def get_vulnerabilities():
    """
    Returns vulnerability records together with
    their related service information.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            vulnerabilities.id,
            vulnerabilities.cve_id,
            vulnerabilities.cvss_score,
            vulnerabilities.severity,
            services.port,
            services.service,
            services.product,
            services.version
        FROM vulnerabilities
        JOIN services
            ON vulnerabilities.service_id = services.id
        ORDER BY vulnerabilities.cvss_score DESC
    """)

    vulnerabilities = cursor.fetchall()

    connection.close()

    return vulnerabilities


def calculate_exposure_score(port):
    """
    Calculates an exposure score based on
    network accessibility.
    """

    network_services = {
        21,
        22,
        23,
        25,
        53,
        80,
        139,
        445,
        2121,
        3306,
        5432,
        5900,
        6667,
        8009,
        8180
    }

    if port in network_services:
        return 3

    return 2


def calculate_service_score(service):
    """
    Calculates a simple service importance score.
    """

    high_value_services = {
        "ssh",
        "ftp",
        "telnet",
        "http",
        "mysql",
        "postgresql",
        "vnc",
        "smb",
        "netbios-ssn",
        "ajp13"
    }

    service_name = (service or "").lower()

    if service_name in high_value_services:
        return 3

    return 2


def calculate_risk_score(
    cvss_score,
    exposure_score,
    service_score
):
    """
    Calculates the LabSec risk score.

    CVSS represents technical severity.
    Exposure and service importance provide
    additional environmental context.
    """

    if cvss_score is None:
        return None

    environmental_factor = (
        exposure_score + service_score
    ) / 6

    risk_score = (
        cvss_score * 0.70
        + environmental_factor * 3
    )

    return round(min(risk_score, 10.0), 2)


def determine_risk_level(risk_score):
    """
    Converts the LabSec risk score into a risk level.
    """

    if risk_score is None:
        return "UNKNOWN"

    if risk_score >= 9.0:
        return "CRITICAL"

    if risk_score >= 7.0:
        return "HIGH"

    if risk_score >= 4.0:
        return "MEDIUM"

    return "LOW"


def build_reasoning(
    cvss_score,
    exposure_score,
    service_score,
    risk_level
):
    """
    Creates a human-readable explanation
    for the calculated risk.
    """

    return (
        f"CVSS score: {cvss_score}. "
        f"Network exposure score: {exposure_score}/3. "
        f"Service importance score: {service_score}/3. "
        f"Final LabSec risk level: {risk_level}."
    )


def save_risk_assessment(
    vulnerability_id,
    cvss_score,
    exposure_score,
    service_score,
    risk_score,
    risk_level,
    reasoning
):
    """
    Saves or updates a risk assessment.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO risk_assessments (
            vulnerability_id,
            cvss_score,
            exposure_score,
            service_score,
            risk_score,
            risk_level,
            reasoning
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(vulnerability_id)
        DO UPDATE SET
            cvss_score = excluded.cvss_score,
            exposure_score = excluded.exposure_score,
            service_score = excluded.service_score,
            risk_score = excluded.risk_score,
            risk_level = excluded.risk_level,
            reasoning = excluded.reasoning
    """, (
        vulnerability_id,
        cvss_score,
        exposure_score,
        service_score,
        risk_score,
        risk_level,
        reasoning
    ))

    connection.commit()
    connection.close()


def assess_vulnerability(vulnerability):
    """
    Performs risk assessment for a single vulnerability.
    """

    (
        vulnerability_id,
        cve_id,
        cvss_score,
        severity,
        port,
        service,
        product,
        version
    ) = vulnerability

    exposure_score = calculate_exposure_score(port)

    service_score = calculate_service_score(service)

    risk_score = calculate_risk_score(
        cvss_score,
        exposure_score,
        service_score
    )

    risk_level = determine_risk_level(risk_score)

    reasoning = build_reasoning(
        cvss_score,
        exposure_score,
        service_score,
        risk_level
    )

    save_risk_assessment(
        vulnerability_id,
        cvss_score,
        exposure_score,
        service_score,
        risk_score,
        risk_level,
        reasoning
    )

    print(
        f"{cve_id} | "
        f"CVSS: {cvss_score} | "
        f"LabSec Risk: {risk_score} | "
        f"{risk_level}"
    )


def display_risk_assessments():
    """
    Displays all stored risk assessments.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            risk_assessments.id,
            vulnerabilities.cve_id,
            vulnerabilities.cvss_score,
            services.port,
            services.product,
            services.version,
            risk_assessments.risk_score,
            risk_assessments.risk_level
        FROM risk_assessments
        JOIN vulnerabilities
            ON risk_assessments.vulnerability_id =
               vulnerabilities.id
        JOIN services
            ON vulnerabilities.service_id =
               services.id
        ORDER BY risk_assessments.risk_score DESC
    """)

    assessments = cursor.fetchall()

    connection.close()

    print("\n" + "=" * 110)
    print("LabSec Risk Assessment")
    print("=" * 110)

    if not assessments:
        print("No risk assessments found.")
        return

    for assessment in assessments:
        (
            assessment_id,
            cve_id,
            cvss_score,
            port,
            product,
            version,
            risk_score,
            risk_level
        ) = assessment

        print(
            f"ID: {assessment_id} | "
            f"Port: {port} | "
            f"{product or '-'} {version or '-'} | "
            f"{cve_id} | "
            f"CVSS: {cvss_score} | "
            f"Risk: {risk_score} | "
            f"{risk_level}"
        )

    print("=" * 110)


def main():
    """
    Main risk assessment workflow.
    """

    print("\nLabSec Risk Engine")
    print("=" * 110)

    vulnerabilities = get_vulnerabilities()

    if not vulnerabilities:
        print("No vulnerabilities found.")
        return

    print(
        f"Vulnerabilities to assess: "
        f"{len(vulnerabilities)}\n"
    )

    for vulnerability in vulnerabilities:
        assess_vulnerability(vulnerability)

    display_risk_assessments()


if __name__ == "__main__":
    main()
