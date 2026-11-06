import shutil
import subprocess
import xml.etree.ElementTree as ET


def nmap_scan(target, ports):

    if not shutil.which("nmap"):

        return {
            "status": "not_installed",
            "open_ports": []
        }, [{
            "severity": "INFO",
            "title": "Nmap unavailable",
            "detail": "Nmap executable was not found.",
            "recommendation": "Install Nmap or run VulnScope with --no-nmap."
        }]

    port_list = ",".join(
        str(int(port))
        for port in sorted(set(ports))
    )

    opened = []
    findings = []

    for ip in target.ips:

        print(f"    [NMAP] Scanning configured ports on {ip}...")

        command = [
            "nmap",
            "-sT",
            "-Pn",
            "-n",
            "-sV",
            "--version-light",
            "-T3",
            "--host-timeout",
            "60s",
            "-p",
            port_list,
            "-oX",
            "-",
            ip
        ]

        try:

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=75,
                check=False
            )

            if result.returncode not in (0, 1):

                raise RuntimeError(
                    (result.stderr or result.stdout)[-1000:]
                )

            root = ET.fromstring(result.stdout)

            for node in root.findall(".//port"):

                state = node.find("state")

                if (
                    state is None
                    or state.get("state") != "open"
                ):
                    continue

                service = node.find("service")

                record = {
                    "ip": ip,
                    "port": int(node.get("portid")),
                    "protocol": node.get("protocol"),
                    "service": (
                        service.get("name", "unknown")
                        if service is not None
                        else "unknown"
                    ),
                    "product": (
                        service.get("product", "")
                        if service is not None
                        else ""
                    ),
                    "version": (
                        service.get("version", "")
                        if service is not None
                        else ""
                    )
                }

                opened.append(record)

                findings.append({
                    "severity": "INFO",
                    "title": (
                        f"Open port {record['port']} "
                        f"({record['service']})"
                    ),
                    "detail": (
                        f"{ip}: {record['product']} "
                        f"{record['version']}"
                    ).strip(),
                    "recommendation": (
                        "Confirm the business need for this service, "
                        "restrict network access and maintain supported software. "
                        "An open port is not automatically a vulnerability."
                    )
                })

        except (
            OSError,
            subprocess.TimeoutExpired,
            ET.ParseError,
            RuntimeError
        ) as error:

            findings.append({
                "severity": "ERROR",
                "title": "Nmap scan error",
                "detail": str(error),
                "recommendation": (
                    "Check Nmap installation, timeout and configured target scope."
                )
            })

    return {
        "status": "completed",
        "open_ports": opened
    }, findings
