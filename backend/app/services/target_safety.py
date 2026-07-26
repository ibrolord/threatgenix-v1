"""Validation target safety checks shared by API and workers."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address
import socket
from urllib.parse import urlparse

BLOCKED_LIVE_TARGET_HOSTNAMES = {"localhost", "metadata.google.internal"}


class LiveTargetSafetyError(ValueError):
    """Raised when a live validation target is unsafe to execute."""


def _blocked_ip_address(value: str | IPv4Address | IPv6Address) -> bool:
    parsed_ip = ip_address(value) if isinstance(value, str) else value
    # ``is_private`` does not cover every non-public range on every supported
    # Python release (for example, carrier-grade NAT). Live validation must only
    # target globally routable addresses.
    return not parsed_ip.is_global


def validate_live_url_target(target: str, *, resolve_dns: bool = True) -> None:
    parsed = urlparse(target.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise LiveTargetSafetyError(
            "Live URL scan targets must be absolute http(s) URLs."
        )
    if parsed.username or parsed.password:
        raise LiveTargetSafetyError(
            "Live URL scan targets must not include embedded credentials."
        )

    hostname = (parsed.hostname or "").strip().casefold()
    if not hostname:
        raise LiveTargetSafetyError("Live URL scan target host is required.")
    if hostname in BLOCKED_LIVE_TARGET_HOSTNAMES or hostname.endswith(".localhost"):
        raise LiveTargetSafetyError(
            "Live scan target resolves to a blocked local or metadata host."
        )

    try:
        literal_ip = ip_address(hostname)
    except ValueError:
        literal_ip = None
    if literal_ip is not None:
        if _blocked_ip_address(literal_ip):
            raise LiveTargetSafetyError(
                "Live scan target must not be a private, loopback, link-local, or metadata IP."
            )
        return

    if not resolve_dns:
        return

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise LiveTargetSafetyError("Live URL scan target port is invalid.") from exc

    try:
        resolved = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise LiveTargetSafetyError(
            "Live scan target host must resolve to public routable DNS."
        ) from exc

    addresses = {item[4][0] for item in resolved if item[4]}
    if not addresses:
        raise LiveTargetSafetyError(
            "Live scan target host must resolve to public routable DNS."
        )
    for address in addresses:
        try:
            blocked = _blocked_ip_address(address)
        except ValueError:
            continue
        if blocked:
            raise LiveTargetSafetyError(
                "Live scan target DNS must resolve only to globally routable IP addresses."
            )
