import subprocess
import xml.etree.ElementTree as ET

from database.database import add_target, add_service


def run_nmap_scan(target):
    """
    Runs an Nmap service/version scan against an authorized lab target.
    Returns Nmap XML output.
    """

    command = [
        "nmap",
        "-sV",
        "-oX",
        "-",
        target
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False
    )

    if result.returncode != 0:
        print("Nmap scan failed.")
        print(result.stderr)
        return None

    return result.stdout


def parse_nmap_xml(xml_output):
    """
    Parses Nmap XML output and extracts open services.
    """

    root = ET.fromstring(xml_output)

    services = []

    for host in root.findall("host"):
        ports = host.find("ports")

        if ports is None:
            continue

        for port in ports.findall("port"):
            state = port.find("state")

            if state is None:
                continue

            if state.get("state") != "open":
                continue

            service = port.find("service")

            service_data = {
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "state": state.get("state"),
                "service": service.get("name") if service is not None else "",
                "product": service.get("product") if service is not None else "",
                "version": service.get("version") if service is not None else ""
            }

            services.append(service_data)

    return services


def save_scan_results(target, services):
    """
    Saves the target and discovered services into SQLite database.
    """

    target_id = add_target(target)

    for service in services:
        add_service(target_id, service)

    return target_id


def print_services(services):
    """
    Displays discovered services in the terminal.
    """

    print("\nDiscovered Services")
    print("=" * 80)

    for service in services:
        print(
            f"{service['port']}/{service['protocol']} | "
            f"{service['service']} | "
            f"{service['product']} "
            f"{service['version']}"
        )

    print("=" * 80)
    print(f"Total open services: {len(services)}")


def main():
    """
    Main application flow.
    """

    target = input("Enter authorized lab target IP: ").strip()

    if not target:
        print("Target IP cannot be empty.")
        return

    print(f"\nStarting Nmap scan for: {target}\n")

    xml_output = run_nmap_scan(target)

    if xml_output is None:
        return

    services = parse_nmap_xml(xml_output)

    print_services(services)

    target_id = save_scan_results(target, services)

    print("\nDatabase")
    print("=" * 80)
    print(f"Target ID: {target_id}")
    print(f"Saved services: {len(services)}")
    print("Scan results saved successfully.")
    print("=" * 80)


if __name__ == "__main__":
    main()
