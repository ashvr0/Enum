from __future__ import annotations

from dataclasses import dataclass


INTERESTING_HEADERS = {
    "server": "Server information exposed",
    "x-powered-by": "Technology information exposed",
    "x-generator": "Generator information exposed",
    "x-aspnet-version": "ASP.NET version exposed",
    "x-aspnetmvc-version": "ASP.NET MVC version exposed",
}


SECURITY_HEADERS = {
    "content-security-policy": "Content Security Policy",
    "strict-transport-security": "HTTP Strict Transport Security",
    "x-content-type-options": "X Content Type Options",
    "x-frame-options": "X Frame Options",
    "referrer-policy": "Referrer Policy",
    "permissions-policy": "Permissions Policy",
}


BACKUP_INDICATORS = (
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".save",
    ".swp",
    "~",
)


@dataclass
class Finding:
    category: str
    title: str
    detail: str
    severity: str


class ExposureScanner:
    def __init__(
        self,
        headers: dict[str, str],
        cookies: list[dict[str, str]],
        discovered_paths: list[dict] | None = None,
    ):
        self.headers = {
            key.lower(): value
            for key, value in headers.items()
        }

        self.cookies = cookies
        self.discovered_paths = (
            discovered_paths or []
        )

    def scan_headers(self) -> list[Finding]:
        findings = []

        for header, description in INTERESTING_HEADERS.items():
            if header in self.headers:
                findings.append(
                    Finding(
                        category="Information Exposure",
                        title=description,
                        detail=(
                            f"{header}: "
                            f"{self.headers[header]}"
                        ),
                        severity="info",
                    )
                )

        for header, description in SECURITY_HEADERS.items():
            if header not in self.headers:
                findings.append(
                    Finding(
                        category="Security Headers",
                        title=f"Missing {description}",
                        detail=(
                            f"The {header} response header "
                            "was not observed."
                        ),
                        severity="low",
                    )
                )

        return findings

    def scan_cookies(self) -> list[Finding]:
        findings = []

        for cookie in self.cookies:
            secure = cookie.get(
                "secure",
                "",
            ).lower() == "true"

            httponly = cookie.get(
                "httponly",
                "",
            ).lower() == "true"

            name = cookie.get(
                "name",
                "unknown",
            )

            if not secure:
                findings.append(
                    Finding(
                        category="Cookies",
                        title="Cookie without Secure flag",
                        detail=name,
                        severity="low",
                    )
                )

            if not httponly:
                findings.append(
                    Finding(
                        category="Cookies",
                        title="Cookie without HttpOnly flag",
                        detail=name,
                        severity="low",
                    )
                )

        return findings

    def scan_paths(self) -> list[Finding]:
        findings = []

        for path in self.discovered_paths:
            status = path.get("status_code")
            url = path.get("url", "")
            content_type = (
                path.get("content_type") or ""
            ).lower()

            if status == 200:
                if path.get("path", "").rstrip(
                    "/"
                ) in {
                    "/.env",
                    "/.git",
                    "/backup",
                    "/backups",
                }:
                    findings.append(
                        Finding(
                            category="Information Exposure",
                            title="Sensitive path accessible",
                            detail=url,
                            severity="medium",
                        )
                    )

                if "text/html" in content_type:
                    findings.append(
                        Finding(
                            category="Web Discovery",
                            title="Accessible web resource",
                            detail=url,
                            severity="info",
                        )
                    )

            if status == 200 and (
                "index of /" in path.get(
                    "path",
                    "",
                ).lower()
            ):
                findings.append(
                    Finding(
                        category="Directory Listing",
                        title="Possible directory listing",
                        detail=url,
                        severity="medium",
                    )
                )

            path_name = path.get(
                "path",
                "",
            ).lower()

            if any(
                indicator in path_name
                for indicator in BACKUP_INDICATORS
            ):
                findings.append(
                    Finding(
                        category="Backup File",
                        title="Possible backup file",
                        detail=url,
                        severity="medium",
                    )
                )

        return findings

    def scan(self) -> list[dict]:
        findings = []

        findings.extend(
            self.scan_headers()
        )

        findings.extend(
            self.scan_cookies()
        )

        findings.extend(
            self.scan_paths()
        )

        return [
            {
                "category": finding.category,
                "title": finding.title,
                "detail": finding.detail,
                "severity": finding.severity,
            }
            for finding in findings
        ]