from __future__ import annotations

import socket
import ssl
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

import requests


@dataclass
class HTTPResult:
    url: str
    status_code: int | None
    final_url: str | None
    redirects: list[str]
    headers: dict[str, str]
    cookies: list[dict[str, str]]
    server: str | None
    content_type: str | None
    response_time: float | None
    body: str
    error: str | None = None


@dataclass
class TLSResult:
    hostname: str
    port: int
    enabled: bool
    version: str | None
    cipher: str | None
    certificate: dict[str, str] | None
    error: str | None = None


class Scanner:
    DEFAULT_TIMEOUT = 10

    def __init__(
        self,
        target: str,
        timeout: float = DEFAULT_TIMEOUT,
        verify_tls: bool = True,
    ):
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.verify_tls = verify_tls

        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": "Enum/0.1.0",
                "Accept": "*/*",
            }
        )

    @staticmethod
    def _normalize_target(target: str) -> str:
        target = target.strip()

        if not target:
            raise ValueError("Target cannot be empty.")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)

        if not parsed.hostname:
            raise ValueError(f"Invalid target: {target}")

        return target.rstrip("/")

    def http_scan(self) -> HTTPResult:
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_tls,
            )

            redirects = [
                history.url
                for history in response.history
            ]

            headers = {
                key: value
                for key, value in response.headers.items()
            }

            cookies = []

            for cookie in response.cookies:
                cookies.append(
                    {
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain or "",
                        "path": cookie.path or "/",
                        "secure": str(cookie.secure),
                        "httponly": str(
                            cookie._rest.get("HttpOnly", "")
                        ),
                    }
                )

            return HTTPResult(
                url=self.target,
                status_code=response.status_code,
                final_url=response.url,
                redirects=redirects,
                headers=headers,
                cookies=cookies,
                server=response.headers.get("Server"),
                content_type=response.headers.get("Content-Type"),
                response_time=response.elapsed.total_seconds(),
                body=response.text[:500_000],
            )

        except requests.RequestException as exc:
            return HTTPResult(
                url=self.target,
                status_code=None,
                final_url=None,
                redirects=[],
                headers={},
                cookies=[],
                server=None,
                content_type=None,
                response_time=None,
                body="",
                error=str(exc),
            )

    def tls_scan(self) -> TLSResult:
        parsed = urlparse(self.target)

        hostname = parsed.hostname

        if not hostname:
            return TLSResult(
                hostname="",
                port=443,
                enabled=False,
                version=None,
                cipher=None,
                certificate=None,
                error="Could not determine hostname.",
            )

        port = parsed.port or 443

        context = ssl.create_default_context()

        if not self.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection(
                (hostname, port),
                timeout=self.timeout,
            ) as raw_socket:

                with context.wrap_socket(
                    raw_socket,
                    server_hostname=hostname,
                ) as tls_socket:

                    certificate = tls_socket.getpeercert()

                    certificate_info = {
                        "subject": self._certificate_name(
                            certificate,
                            "subject",
                        ),
                        "issuer": self._certificate_name(
                            certificate,
                            "issuer",
                        ),
                        "version": str(
                            certificate.get("version", "")
                        ),
                        "serial_number": str(
                            certificate.get("serialNumber", "")
                        ),
                        "not_before": str(
                            certificate.get("notBefore", "")
                        ),
                        "not_after": str(
                            certificate.get("notAfter", "")
                        ),
                    }

                    cipher_info = tls_socket.cipher()

                    cipher_name = (
                        cipher_info[0]
                        if cipher_info
                        else None
                    )

                    return TLSResult(
                        hostname=hostname,
                        port=port,
                        enabled=True,
                        version=tls_socket.version(),
                        cipher=cipher_name,
                        certificate=certificate_info,
                    )

        except (OSError, ssl.SSLError) as exc:
            return TLSResult(
                hostname=hostname,
                port=port,
                enabled=False,
                version=None,
                cipher=None,
                certificate=None,
                error=str(exc),
            )

    @staticmethod
    def _certificate_name(
        certificate: dict,
        field: str,
    ) -> str:
        values = certificate.get(field, [])

        for group in values:
            for key, value in group:
                if key == "commonName":
                    return value

        return ""

    def scan(self) -> dict:
        http_result = self.http_scan()
        tls_result = self.tls_scan()

        return {
            "target": self.target,
            "http": asdict(http_result),
            "tls": asdict(tls_result),
        }