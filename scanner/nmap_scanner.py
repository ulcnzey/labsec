import subprocess
import xml.etree.ElementTree as ET


def run_nmap_scan(target):
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
    root = ET.fromstring(xml_output)

    services = []

    for host in root.findall("host"):
        ports = host.find("ports")

        if ports is None:
            continue

        for port in ports.findall("port"):
            state = port.find("state")

            if state is None or state.get("state") != "open":
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


if __name__ == "__main__":
    target = input("Enter authorized lab target IP: ").strip()

    if not target:
        print("Target IP cannot be empty.")
    else:
        print(f"\nStarting Nmap scan for: {target}\n")

        xml_output = run_nmap_scan(target)

        if xml_output:
            services = parse_nmap_xml(xml_output)

            print("\nDiscovered Services")
            print("=" * 70)

            for service in services:
                print(
                    f"{service['port']}/{service['protocol']} | "
                    f"{service['service']} | "
                    f"{service['product']} "
                    f"{service['version']}"
                )

            print("=" * 70)
            print(f"Total open services: {len(services)}")
