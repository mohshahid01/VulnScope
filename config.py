from pathlib import Path
import json

BASE_DIR = Path(__file__).resolve().parent

REPORTS = BASE_DIR / "reports"
LOGS = BASE_DIR / "logs"

REPORTS.mkdir(exist_ok=True)
LOGS.mkdir(exist_ok=True)

USER_AGENT = "VulnScope/1.0"

def scope():
    scope_file = BASE_DIR / "scope.json"

    if not scope_file.exists():
        raise RuntimeError("scope.json is missing.")

    with scope_file.open("r", encoding="utf-8") as file:
        data = json.load(file)

    required = {
        "allowed_hosts",
        "allowed_networks",
        "allow_public_ips_for_allowlisted_hosts",
        "allowed_web_ports",
        "allowed_scan_ports",
        "max_http_requests",
        "request_delay_seconds",
        "request_timeout_seconds",
        "directory_paths"
    }

    missing = required - data.keys()

    if missing:
        raise RuntimeError(
            "Missing scope.json keys: "
            + ", ".join(sorted(missing))
        )

    if data["max_http_requests"] < 1:
        raise RuntimeError("max_http_requests must be positive.")

    if data["request_timeout_seconds"] <= 0:
        raise RuntimeError("request_timeout_seconds must be positive.")

    return data
