import socket
import ssl

from datetime import datetime, timezone


def tls_scan(target):

    info = {}
    findings = []

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (target.ips[0], target.port),
            timeout=6
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=target.hostname
            ) as connection:

                certificate = connection.getpeercert()

                info = {
                    "tls_version": connection.version(),
                    "cipher": connection.cipher(),
                    "issuer": certificate.get("issuer")
                }

                expiry = certificate.get("notAfter")

                if expiry:

                    end = datetime.strptime(
                        expiry,
                        "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)

                    days = (
                        end - datetime.now(timezone.utc)
                    ).days

                    info.update({
                        "expires_at": end.isoformat(),
                        "days_remaining": days
                    })

                    if days < 0:
                        severity = "HIGH"
                        title = "TLS certificate expired"

                    elif days <= 30:
                        severity = "MEDIUM"
                        title = "TLS certificate expires soon"

                    else:
                        severity = "INFO"
                        title = "TLS certificate date check passed"

                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": f"{days} days remaining.",
                        "recommendation": (
                            "Renew an expired or soon-to-expire certificate "
                            "and continue monitoring certificate validity."
                        )
                    })

    except (OSError, ssl.SSLError) as error:

        info["error"] = str(error)

        findings.append({
            "severity": "ERROR",
            "title": "TLS validation failed",
            "detail": str(error),
            "recommendation": (
                "Check the hostname, trust chain, certificate and HTTPS service. "
                "Do not disable certificate verification."
            )
        })

    return info, findings
