from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin

import requests


@dataclass
class DiscoveryResult:
    robots: dict
    sitemap: dict
    security_txt: dict


class DiscoveryScanner:
    def __init__(
        self,
        base_url: str,
        timeout: float = 8.0,
        verify_tls: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_tls = verify_tls

        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": "Enum/0.1.0",
            }
        )

    def fetch(self, path: str) -> dict:
        url = urljoin(
            f"{self.base_url}/",
            path.lstrip("/"),
        )

        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_tls,
            )

            return {
                "url": url,
                "status_code": response.status_code,
                "content_type": response.headers.get(
                    "Content-Type"
                ),
                "content": response.text[:100_000],
            }

        except requests.RequestException as exc:
            return {
                "url": url,
                "status_code": None,
                "content_type": None,
                "content": "",
                "error": str(exc),
            }

    def parse_robots(self, result: dict) -> dict:
        content = result.get("content", "")

        disallowed = []
        sitemaps = []

        for line in content.splitlines():
            line = line.strip()

            if not line:
                continue

            if line.lower().startswith("disallow:"):
                value = line.split(
                    ":",
                    1,
                )[1].strip()

                if value:
                    disallowed.append(value)

            elif line.lower().startswith("sitemap:"):
                value = line.split(
                    ":",
                    1,
                )[1].strip()

                if value:
                    sitemaps.append(value)

        return {
            **result,
            "disallowed": disallowed,
            "sitemaps": sitemaps,
        }

    def parse_sitemap(self, result: dict) -> dict:
        content = result.get("content", "")

        locations = re.findall(
            r"<loc>\s*(.*?)\s*</loc>",
            content,
            flags=re.IGNORECASE,
        )

        return {
            **result,
            "locations": locations[:1000],
        }

    def scan(self) -> dict:
        robots = self.fetch("/robots.txt")
        sitemap = self.fetch("/sitemap.xml")

        security = self.fetch(
            "/.well-known/security.txt"
        )

        security_alt = self.fetch(
            "/security.txt"
        )

        if (
            security.get("status_code") is None
            or security.get("status_code") >= 400
        ):
            if security_alt.get("status_code", 999) < 400:
                security = security_alt

        return {
            "robots": self.parse_robots(robots),
            "sitemap": self.parse_sitemap(sitemap),
            "security_txt": security,
        }