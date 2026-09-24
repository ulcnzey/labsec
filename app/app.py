"""
LabSec Flask Web Application

Provides the web dashboard and coordinates:
- Nmap scanning
- Service discovery
- CVE research
- Risk analysis
"""

import sqlite3

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

from scanner.nmap_scanner import (
    run_nmap_scan,
    parse_nmap_xml,
    save_scan_results
)

from vulnerability.cve_manager import (
    research_service
)

from risk.risk_engine import (
    get_vulnerabilities,
    assess_vulnerability
)


app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

app.secret_key = "labsec-development-key"

DATABASE_PATH = "database/labsec.db"


# ============================================================
# DATABASE
# ============================================================

def get_connection():
    """
    Creates a connection to the LabSec SQLite database.
    """
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


# ============================================================
# DASHBOARD DATA
# ============================================================

def get_dashboard_data():
    """
    Returns dashboard data for the latest scan only.

    Historical scans remain stored in the database,
    but the dashboard represents the most recent assessment.
    """

    connection = get_connection()

    # --------------------------------------------------------
    # Latest scan
    # --------------------------------------------------------

    latest_scan = connection.execute(
        """
        SELECT
            scans.id AS scan_id,
            scans.scanned_at,
            targets.ip_address
        FROM scans
        JOIN targets
            ON scans.target_id = targets.id
        ORDER BY scans.id DESC
        LIMIT 1
        """
    ).fetchone()

    if latest_scan is None:
        connection.close()

        return {
            "target": None,
            "scan": None,
            "services": [],
            "vulnerability_count": 0,
            "critical_count": 0,
            "max_cvss": 0,
            "risk_distribution": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0
            },
            "latest_findings": []
        }

    scan_id = latest_scan["scan_id"]

    # --------------------------------------------------------
    # Services belonging to latest scan
    # --------------------------------------------------------

    services = connection.execute(
        """
        SELECT
            id,
            port,
            protocol,
            state,
            service,
            product,
            version
        FROM services
        WHERE scan_id = ?
        ORDER BY CAST(port AS INTEGER)
        """,
        (scan_id,)
    ).fetchall()

    # --------------------------------------------------------
    # Vulnerability statistics for latest scan
    # --------------------------------------------------------

    vulnerability_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM vulnerabilities
        JOIN services
            ON vulnerabilities.service_id = services.id
        WHERE services.scan_id = ?
        """,
        (scan_id,)
    ).fetchone()[0]

    critical_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM vulnerabilities
        JOIN services
            ON vulnerabilities.service_id = services.id
        WHERE services.scan_id = ?
          AND (
              vulnerabilities.severity = 'CRITICAL'
              OR vulnerabilities.cvss_score >= 9.0
          )
        """,
        (scan_id,)
    ).fetchone()[0]

    max_cvss_result = connection.execute(
        """
        SELECT MAX(vulnerabilities.cvss_score)
        FROM vulnerabilities
        JOIN services
            ON vulnerabilities.service_id = services.id
        WHERE services.scan_id = ?
        """,
        (scan_id,)
    ).fetchone()

    max_cvss = max_cvss_result[0] if max_cvss_result[0] is not None else 0

    # --------------------------------------------------------
    # Risk distribution for latest scan
    # --------------------------------------------------------

    risk_rows = connection.execute(
        """
        SELECT
            risk_assessments.risk_level,
            COUNT(*) AS count
        FROM risk_assessments
        JOIN vulnerabilities
            ON risk_assessments.vulnerability_id = vulnerabilities.id
        JOIN services
            ON vulnerabilities.service_id = services.id
        WHERE services.scan_id = ?
        GROUP BY risk_assessments.risk_level
        """,
        (scan_id,)
    ).fetchall()

    risk_distribution = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for row in risk_rows:
        level = row["risk_level"]

        if level in risk_distribution:
            risk_distribution[level] = row["count"]

    # --------------------------------------------------------
    # Latest findings
    # --------------------------------------------------------

    latest_findings = connection.execute(
        """
        SELECT
            vulnerabilities.id,
            vulnerabilities.cve_id,
            vulnerabilities.description,
            vulnerabilities.cvss_score,
            vulnerabilities.severity,
            risk_assessments.risk_score,
            risk_assessments.risk_level,
            services.port,
            services.service,
            services.product,
            services.version
        FROM vulnerabilities
        JOIN services
            ON vulnerabilities.service_id = services.id
        LEFT JOIN risk_assessments
            ON vulnerabilities.id = risk_assessments.vulnerability_id
        WHERE services.scan_id = ?
        ORDER BY
            COALESCE(risk_assessments.risk_score,
                     vulnerabilities.cvss_score) DESC
        LIMIT 10
        """,
        (scan_id,)
    ).fetchall()

    connection.close()

    return {
        "target": latest_scan["ip_address"],
        "scan": latest_scan,
        "services": services,
        "vulnerability_count": vulnerability_count,
        "critical_count": critical_count,
        "max_cvss": max_cvss,
        "risk_distribution": risk_distribution,
        "latest_findings": latest_findings
    }


# ============================================================
# SCAN SERVICES
# ============================================================

def get_services_for_scan(scan_id):
    """
    Returns services discovered during a specific scan.
    """

    connection = get_connection()

    services = connection.execute(
        """
        SELECT
            id,
            port,
            protocol,
            state,
            service,
            product,
            version
        FROM services
        WHERE scan_id = ?
        ORDER BY CAST(port AS INTEGER)
        """,
        (scan_id,)
    ).fetchall()

    connection.close()

    return services


# ============================================================
# CVE RESEARCH
# ============================================================

def run_vulnerability_analysis(scan_id):
    """
    Performs CVE research only for services belonging
    to the current scan.
    """

    services = get_services_for_scan(scan_id)

    print("\n" + "=" * 80)
    print("Starting CVE research")
    print("=" * 80)

    for service in services:
        service_data = (
            service["id"],
            service["port"],
            service["service"],
            service["product"],
            service["version"]
        )

        try:
            research_service(service_data)

        except Exception as error:
            print(
                f"CVE research failed for service "
                f"{service['id']}: {error}"
            )

    print("=" * 80)


# ============================================================
# RISK ANALYSIS
# ============================================================

def get_vulnerabilities_for_scan(scan_id):
    """
    Returns vulnerabilities belonging only to a specific scan.

    Vulnerabilities are connected to scans through:
        vulnerabilities -> services -> scans
    """

    connection = get_connection()

    vulnerabilities = connection.execute(
        """
        SELECT
            vulnerabilities.id,
            vulnerabilities.service_id,
            vulnerabilities.cve_id,
            vulnerabilities.description,
            vulnerabilities.cvss_score,
            vulnerabilities.severity,
            vulnerabilities.source
        FROM vulnerabilities
        JOIN services
            ON vulnerabilities.service_id = services.id
        WHERE services.scan_id = ?
        ORDER BY vulnerabilities.id
        """,
        (scan_id,)
    ).fetchall()

    connection.close()

    return vulnerabilities


def run_risk_analysis(scan_id):
    """
    Performs risk analysis only for vulnerabilities
    discovered during the current scan.
    """

    vulnerabilities = get_vulnerabilities_for_scan(scan_id)

    print("\n" + "=" * 80)
    print("Starting risk analysis")
    print("=" * 80)

    if not vulnerabilities:
        print("No vulnerabilities available for risk analysis.")
        print("=" * 80)
        return

    for vulnerability in vulnerabilities:

        try:
            assess_vulnerability(
                (
                    vulnerability["id"],
                    vulnerability["service_id"],
                    vulnerability["cve_id"],
                    vulnerability["description"],
                    vulnerability["cvss_score"],
                    vulnerability["severity"],
                    vulnerability["source"]
                )
            )

        except (TypeError, ValueError) as error:
            print(
                f"Risk analysis skipped for "
                f"{vulnerability['cve_id']}: {error}"
            )

        except Exception as error:
            print(
                f"Risk analysis failed for "
                f"{vulnerability['cve_id']}: {error}"
            )

    print("=" * 80)


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():
    """
    Main LabSec dashboard.
    """

    dashboard_data = get_dashboard_data()

    return render_template(
        "dashboard.html",
        **dashboard_data
    )


# ============================================================
# START NEW SCAN
# ============================================================

@app.route("/scan", methods=["POST"])
def scan_target():
    """
    Starts a complete LabSec assessment:

    1. Nmap scan
    2. Service discovery
    3. Database storage
    4. CVE research
    5. Risk analysis
    """

    target_ip = request.form.get(
        "target_ip",
        ""
    ).strip()

    if not target_ip:
        flash(
            "Target IP cannot be empty.",
            "error"
        )

        return redirect(url_for("dashboard"))

    print("\n" + "=" * 80)
    print(
        f"Starting LabSec scan: {target_ip}"
    )
    print("=" * 80)

    # --------------------------------------------------------
    # Nmap
    # --------------------------------------------------------

    xml_output = run_nmap_scan(target_ip)

    if xml_output is None:
        flash(
            "Nmap scan failed.",
            "error"
        )

        return redirect(url_for("dashboard"))

    # --------------------------------------------------------
    # Parse results
    # --------------------------------------------------------

    services = parse_nmap_xml(xml_output)

    if not services:
        flash(
            "No open services were discovered.",
            "warning"
        )

        return redirect(url_for("dashboard"))

    print(
        f"Discovered {len(services)} open services."
    )

    # --------------------------------------------------------
    # Save scan
    # --------------------------------------------------------

    target_id, scan_id, service_ids = save_scan_results(
        target_ip,
        services
    )

    print(f"Target ID : {target_id}")
    print(f"Scan ID   : {scan_id}")
    print(f"Services  : {len(service_ids)}")

    # --------------------------------------------------------
    # CVE research
    # --------------------------------------------------------

    run_vulnerability_analysis(scan_id)

    # --------------------------------------------------------
    # Risk analysis
    # --------------------------------------------------------

    run_risk_analysis(scan_id)

    print("\nLabSec scan completed")
    print("=" * 80)

    flash(
        f"Scan completed successfully. "
        f"{len(services)} open services discovered.",
        "success"
    )

    return redirect(url_for("dashboard"))


# ============================================================
# REPORT
# ============================================================

@app.route("/report")
def generate_report_route():
    """
    Generates the latest LabSec security report.
    """

    from reports.report_generator import generate_report

    success = generate_report()

    if success:
        flash(
            "Security report generated successfully.",
            "success"
        )
    else:
        flash(
            "Report generation failed.",
            "error"
        )

    return redirect(url_for("dashboard"))


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():
    """
    Simple application health check.
    """

    return {
        "status": "ok",
        "application": "LabSec"
    }


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
