import requests

from bs4 import BeautifulSoup
from urllib.parse import urlsplit, urljoin

from config import USER_AGENT, scope
from core.rate_limiter import RateLimitExceeded


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "MEDIUM",
        "Define a restrictive Content-Security-Policy."
    ),
    "X-Content-Type-Options": (
        "LOW",
        "Set X-Content-Type-Options: nosniff."
    ),
    "X-Frame-Options": (
        "LOW",
        "Set X-Frame-Options or CSP frame-ancestors."
    ),
    "Referrer-Policy": (
        "LOW",
        "Set a restrictive Referrer-Policy."
    ),
    "Permissions-Policy": (
        "INFO",
        "Restrict browser features not required by the application."
    ),
    "Strict-Transport-Security": (
        "MEDIUM",
        "Configure HSTS after HTTPS is correctly deployed."
    )
}


def create_session():

    session = requests.Session()

    # Do not inherit proxy settings from the environment.
    session.trust_env = False

    session.headers.update({
        "User-Agent": USER_AGENT
    })

    return session


def add_finding(findings, severity, title, detail, recommendation):

    findings.append({
        "severity": severity,
        "title": title,
        "detail": str(detail),
        "recommendation": recommendation
    })


def web_scan(target, limiter, paths):

    findings = []

    data = {
        "headers": {},
        "status": None,
        "discovered_paths": []
    }

    session = create_session()

    try:

        print("    [HTTP] Requesting target...")

        limiter.wait()

        response = session.get(
            target.url,
            timeout=scope()["request_timeout_seconds"],
            allow_redirects=False,
            verify=True
        )

        data.update({
            "status": response.status_code,
            "headers": dict(response.headers),
            "content_type": response.headers.get(
                "Content-Type", ""
            ),
            "server": response.headers.get("Server"),
            "powered_by": response.headers.get("X-Powered-By"),
            "title": None,
            "redirect": response.headers.get("Location")
        })

        if 300 <= response.status_code < 400:

            add_finding(
                findings,
                "INFO",
                "Redirect observed",
                (
                    f"HTTP {response.status_code} to "
                    f"{data['redirect']}. Redirect was not followed."
                ),
                "Review the redirect destination and expected behavior."
            )

        present_headers = {
            header.lower()
            for header in response.headers
        }

        for header, (severity, advice) in SECURITY_HEADERS.items():

            if header.lower() not in present_headers:

                if (
                    header == "Strict-Transport-Security"
                    and target.scheme != "https"
                ):
                    continue

                add_finding(
                    findings,
                    severity,
                    f"Missing security header: {header}",
                    f"Response does not include {header}.",
                    advice
                )

        for header, key in (
            ("Server", "server"),
            ("X-Powered-By", "powered_by")
        ):

            if data.get(key):

                add_finding(
                    findings,
                    "LOW",
                    f"{header} banner disclosed",
                    data[key],
                    (
                        "Remove unnecessary product/version disclosure. "
                        "A banner alone is not proof of a vulnerability."
                    )
                )

        content_type = data["content_type"].lower()

        if "html" in content_type:

            soup = BeautifulSoup(
                response.text[:300000],
                "html.parser"
            )

            if soup.title:
                data["title"] = soup.title.get_text(
                    strip=True
                )[:200]

        add_finding(
            findings,
            "INFO",
            "HTTP response received",
            (
                f"HTTP {response.status_code}; "
                f"{data['content_type'] or 'content type not supplied'}."
            ),
            "Review whether the response is expected and publicly accessible."
        )

        response.close()

    except RateLimitExceeded as error:

        add_finding(
            findings,
            "INFO",
            "HTTP request limit reached",
            str(error),
            "Review the configured request budget."
        )

    except requests.RequestException as error:

        data["error"] = str(error)

        add_finding(
            findings,
            "ERROR",
            "HTTP request failed",
            str(error),
            (
                "Check target reachability, DNS and TLS. "
                "Certificate verification remains enabled."
            )
        )

    finally:
        session.close()

    # Conservative same-origin path discovery.
    base = target.url.rstrip("/") + "/"

    base_parts = urlsplit(base)

    origin = (
        base_parts.scheme,
        base_parts.netloc
    )

    session = create_session()

    for path in paths:

        path = str(path).lstrip("/")

        if not path or ".." in path.split("/"):
            continue

        url = urljoin(base, path)

        parsed = urlsplit(url)

        if (parsed.scheme, parsed.netloc) != origin:
            continue

        try:

            limiter.wait()

            response = session.get(
                url,
                timeout=scope()["request_timeout_seconds"],
                allow_redirects=False,
                verify=True,
                stream=True
            )

            status = response.status_code

            content_type = response.headers.get(
                "Content-Type", ""
            )

            response.close()

            if status in (200, 204, 301, 302, 401, 403):

                item = {
                    "path": "/" + path,
                    "status": status,
                    "content_type": content_type
                }

                data["discovered_paths"].append(item)

                print(
                    f"    [FOUND] {status} {item['path']}"
                )

                add_finding(
                    findings,
                    "INFO",
                    f"Path discovered: {item['path']}",
                    (
                        f"HTTP {status}; "
                        f"{content_type or 'content type unknown'}."
                    ),
                    (
                        "Verify that this path is intended to be reachable. "
                        "HTTP 401 or 403 is not proof of a vulnerability."
                    )
                )

        except RateLimitExceeded:

            print(
                "    [LIMIT] Request budget exhausted; discovery stopped."
            )

            break

        except requests.RequestException as error:

            print(
                f"    [WARN] {path}: {error}"
            )

    session.close()

    return data, findings
