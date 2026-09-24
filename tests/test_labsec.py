import unittest

from scanner.nmap_scanner import parse_nmap_xml
from risk.risk_engine import (
    calculate_exposure_score,
    calculate_service_score,
    calculate_risk_score,
    determine_risk_level,
)


class TestNmapParser(unittest.TestCase):
    """Tests for Nmap XML parsing."""

    def test_parse_open_service(self):
        xml = """
        <nmaprun>
            <host>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service
                            name="http"
                            product="Apache httpd"
                            version="2.2.8"
                        />
                    </port>
                </ports>
            </host>
        </nmaprun>
        """

        services = parse_nmap_xml(xml)

        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["port"], "80")
        self.assertEqual(services[0]["protocol"], "tcp")
        self.assertEqual(services[0]["state"], "open")
        self.assertEqual(services[0]["service"], "http")
        self.assertEqual(services[0]["product"], "Apache httpd")
        self.assertEqual(services[0]["version"], "2.2.8")

    def test_ignore_closed_service(self):
        xml = """
        <nmaprun>
            <host>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="closed"/>
                        <service
                            name="ssh"
                            product="OpenSSH"
                            version="4.7"
                        />
                    </port>
                </ports>
            </host>
        </nmaprun>
        """

        services = parse_nmap_xml(xml)

        self.assertEqual(len(services), 0)

    def test_parse_multiple_services(self):
        xml = """
        <nmaprun>
            <host>
                <ports>
                    <port protocol="tcp" portid="21">
                        <state state="open"/>
                        <service
                            name="ftp"
                            product="vsftpd"
                            version="2.3.4"
                        />
                    </port>

                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service
                            name="http"
                            product="Apache httpd"
                            version="2.2.8"
                        />
                    </port>
                </ports>
            </host>
        </nmaprun>
        """

        services = parse_nmap_xml(xml)

        self.assertEqual(len(services), 2)
        self.assertEqual(services[0]["port"], "21")
        self.assertEqual(services[1]["port"], "80")


class TestRiskEngine(unittest.TestCase):
    """Tests for the LabSec risk calculation model."""

    def test_exposure_score(self):
        self.assertEqual(
            calculate_exposure_score(80),
            3
        )

        self.assertEqual(
            calculate_exposure_score(21),
            3
        )

        self.assertEqual(
            calculate_exposure_score(9999),
            2
        )

    def test_service_score(self):
        self.assertEqual(
            calculate_service_score("http"),
            3
        )

        self.assertEqual(
            calculate_service_score("ssh"),
            3
        )

        self.assertEqual(
            calculate_service_score("unknown"),
            2
        )

    def test_risk_score_range(self):
        score = calculate_risk_score(
            cvss_score=9.8,
            exposure_score=3,
            service_score=3
        )

        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 10)

    def test_high_cvss_produces_high_risk(self):
        score = calculate_risk_score(
            cvss_score=9.8,
            exposure_score=3,
            service_score=3
        )

        self.assertGreaterEqual(score, 9)

    def test_risk_levels(self):
        self.assertEqual(
            determine_risk_level(9.5),
            "CRITICAL"
        )

        self.assertEqual(
            determine_risk_level(8.0),
            "HIGH"
        )

        self.assertEqual(
            determine_risk_level(5.0),
            "MEDIUM"
        )

        self.assertEqual(
            determine_risk_level(2.0),
            "LOW"
        )

    def test_risk_level_boundary_values(self):
        self.assertEqual(
            determine_risk_level(9.0),
            "CRITICAL"
        )

        self.assertEqual(
            determine_risk_level(7.0),
            "HIGH"
        )

        self.assertEqual(
            determine_risk_level(4.0),
            "MEDIUM"
        )

        self.assertEqual(
            determine_risk_level(3.99),
            "LOW"
        )


class TestRiskCalculationConsistency(unittest.TestCase):
    """Tests for consistent risk calculation behavior."""

    def test_same_inputs_produce_same_score(self):
        score_1 = calculate_risk_score(7.5, 3, 3)
        score_2 = calculate_risk_score(7.5, 3, 3)

        self.assertEqual(score_1, score_2)

    def test_score_is_rounded(self):
        score = calculate_risk_score(7.3, 3, 3)

        self.assertEqual(
            score,
            round(score, 2)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
