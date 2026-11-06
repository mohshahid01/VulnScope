import argparse
import logging
import sys

from datetime import datetime, timezone

from config import scope, LOGS

from core.target_validator import (
    validate_target,
    TargetValidationError
)

from core.rate_limiter import RateLimiter

from modules.web_checks import web_scan
from modules.nmap_scan import nmap_scan
from modules.tls_scan import tls_scan

from intelligence.risk import rank

from reporting.reports import generate


logging.basicConfig(
    filename=LOGS / "vulnscope.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)


def main():

    print("\n==========================================")
    print("       VULNSCOPE 1.0 SECURITY SCANNER")
    print("==========================================\n")

    parser = argparse.ArgumentParser(
        description=(
            "Non-destructive web and network assessment tool."
        )
    )

    parser.add_argument(
        "target",
        help="HTTP/HTTPS target URL within configured scope"
    )

    parser.add_argument(
        "--no-nmap",
        action="store_true",
        help="Skip Nmap service detection"
    )

    args = parser.parse_args()

    try:

        print("[1/5] Validating target...")

        target = validate_target(args.target)

        print(f"[OK] URL: {target.url}")
        print(f"[OK] Host: {target.hostname}")
        print(f"[OK] IP addresses: {', '.join(target.ips)}")

        cfg = scope()

        limiter = RateLimiter(
            cfg["max_http_requests"],
            cfg["request_delay_seconds"]
        )

        started = datetime.now(
            timezone.utc
        ).isoformat()

        metadata = {
            "project": "VulnScope",
            "version": "1.0",
            "target": target.url,
            "hostname": target.hostname,
            "resolved_ips": list(target.ips),
            "started": started
        }

        findings = []

        # --------------------------------
        # HTTP checks
        # --------------------------------

        print("\n[2/5] HTTP security checks...")

        web_data, web_findings = web_scan(
            target,
            limiter,
            cfg["directory_paths"]
        )

        metadata["web"] = web_data
        findings.extend(web_findings)

        # --------------------------------
        # TLS checks
        # --------------------------------

        if target.scheme == "https":

            print("\n[3/5] TLS certificate checks...")

            tls_data, tls_findings = tls_scan(target)

            metadata["tls"] = tls_data
            findings.extend(tls_findings)

        else:

            print("\n[3/5] TLS checks skipped: HTTP target.")

            metadata["tls"] = {
                "status": "skipped",
                "reason": "HTTP target"
            }

        # --------------------------------
        # Nmap checks
        # --------------------------------

        if not args.no_nmap:

            print("\n[4/5] Nmap service detection...")

            nmap_data, nmap_findings = nmap_scan(
                target,
                cfg["allowed_scan_ports"]
            )

            metadata["nmap"] = nmap_data
            findings.extend(nmap_findings)

        else:

            print("\n[4/5] Nmap skipped.")

            metadata["nmap"] = {
                "status": "skipped"
            }

        # --------------------------------
        # Risk ranking
        # --------------------------------

        findings = rank(findings)

        metadata["finished"] = datetime.now(
            timezone.utc
        ).isoformat()

        metadata["http_requests_used"] = limiter.used()

        # --------------------------------
        # Terminal output
        # --------------------------------

        print("\n==========================================")
        print("              SCAN FINDINGS")
        print("==========================================")

        if not findings:

            print("No findings returned by enabled checks.")

        for index, finding in enumerate(findings, 1):

            print(
                f"\n{index}. "
                f"[{finding['severity']}] "
                f"{finding['title']}"
            )

            print(
                f"   Risk score: {finding['risk_score']}"
            )

            print(
                f"   Evidence: {finding.get('detail', '')}"
            )

            print(
                f"   Recommendation: "
                f"{finding.get('recommendation', '')}"
            )

        # --------------------------------
        # Generate reports
        # --------------------------------

        print("\n[5/5] Generating reports...")

        report_paths = generate(
            metadata,
            findings
        )

        print("\n==========================================")
        print("             REPORT FILES")
        print("==========================================")

        for report_type, path in report_paths.items():

            print(
                f"[+] {report_type}: {path}"
            )

        print(
            f"\n[+] HTTP requests used: {limiter.used()}"
        )

        print("\n[+] Scan completed.")

        logging.info(
            "Scan completed. Target=%s Findings=%d",
            target.url,
            len(findings)
        )

    except TargetValidationError as error:

        print(f"\n[REJECTED] {error}")

        logging.warning(
            "Target rejected: %s",
            error
        )

        sys.exit(2)

    except KeyboardInterrupt:

        print("\n[STOP] Scan interrupted by user.")

        sys.exit(130)

    except Exception:

        logging.exception(
            "Unexpected scan failure"
        )

        print(
            "\n[ERROR] Unexpected failure. "
            "Check logs/vulnscope.log."
        )

        sys.exit(1)


if __name__ == "__main__":
    main()
