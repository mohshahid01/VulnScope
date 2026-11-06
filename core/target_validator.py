import ipaddress
import re
import socket

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from config import scope


class TargetValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    original_url: str
    url: str
    hostname: str
    scheme: str
    port: int
    ips: tuple


def validate_target(value):

    if not isinstance(value, str):
        raise TargetValidationError("Target must be a URL.")

    value = value.strip()

    if not value or len(value) > 2048:
        raise TargetValidationError(
            "Target must contain 1–2048 characters."
        )

    if any(
        c.isspace() or ord(c) < 32 or c == "\\"
        for c in value
    ):
        raise TargetValidationError(
            "Whitespace, control characters and backslashes are not allowed."
        )

    try:
        parsed = urlsplit(value)

        raw_host = parsed.hostname
        supplied_port = parsed.port

    except ValueError as error:
        raise TargetValidationError(
            f"Malformed URL: {error}"
        ) from error

    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        raise TargetValidationError(
            "Only HTTP and HTTPS URLs are supported."
        )

    if not parsed.netloc or not raw_host:
        raise TargetValidationError(
            "Enter a complete URL including its hostname."
        )

    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError(
            "URLs containing credentials are not accepted."
        )

    if parsed.fragment:
        raise TargetValidationError(
            "URL fragments are not accepted."
        )

    host = raw_host.rstrip(".").lower()

    try:
        ip_obj = ipaddress.ip_address(host)
        host = ip_obj.compressed

    except ValueError:

        if "%" in host or re.fullmatch(r"[0-9.]+", host):
            raise TargetValidationError(
                "Invalid or ambiguous hostname/IP notation."
            )

        try:
            host = host.encode("idna").decode("ascii")

        except UnicodeError as error:
            raise TargetValidationError(
                "Invalid hostname."
            ) from error

        if len(host) > 253:
            raise TargetValidationError("Hostname is too long.")

        labels = host.split(".")

        for label in labels:
            if not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            ):
                raise TargetValidationError(
                    "Invalid hostname label."
                )

        ip_obj = None

    cfg = scope()

    port = supplied_port or (
        443 if scheme == "https" else 80
    )

    if port not in cfg["allowed_web_ports"]:
        raise TargetValidationError(
            f"Port {port} is not in the configured web-port list."
        )

    allowed_hosts = {
        item.lower().rstrip(".")
        for item in cfg["allowed_hosts"]
    }

    if ip_obj is None and host not in allowed_hosts:
        raise TargetValidationError(
            f"Hostname is not in the configured scope: {host}"
        )

    if ip_obj is not None:
        ips = (ip_obj.compressed,)

    else:
        try:
            records = socket.getaddrinfo(
                host,
                port,
                type=socket.SOCK_STREAM
            )

            ips = tuple(sorted({
                ipaddress.ip_address(record[4][0]).compressed
                for record in records
            }))

        except (OSError, ValueError, IndexError) as error:
            raise TargetValidationError(
                f"DNS resolution failed: {error}"
            ) from error

    if not ips:
        raise TargetValidationError(
            "Hostname did not resolve to an IP address."
        )

    networks = [
        ipaddress.ip_network(network, strict=False)
        for network in cfg["allowed_networks"]
    ]

    for address in ips:

        ip = ipaddress.ip_address(address)

        in_network = any(
            ip in network
            for network in networks
        )

        public_allowed = (
            cfg["allow_public_ips_for_allowlisted_hosts"]
            and host in allowed_hosts
            and ip.is_global
            and ip_obj is None
        )

        if not (in_network or public_allowed):
            raise TargetValidationError(
                f"Resolved IP is outside configured scope: {address}"
            )

    display_host = (
        f"[{host}]"
        if ip_obj is not None and ip_obj.version == 6
        else host
    )

    default_port = 443 if scheme == "https" else 80

    authority = (
        display_host
        if port == default_port
        else f"{display_host}:{port}"
    )

    clean_url = urlunsplit((
        scheme,
        authority,
        parsed.path or "/",
        parsed.query,
        ""
    ))

    return Target(
        original_url=value,
        url=clean_url,
        hostname=host,
        scheme=scheme,
        port=port,
        ips=ips
    )
