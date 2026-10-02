from __future__ import annotations

import re


class TechnologyScanner:
    def __init__(
        self,
        html: str,
        headers: dict[str, str],
    ):
        self.html = html
        self.headers = {
            key.lower(): value
            for key, value in headers.items()
        }

    def detect_server(self) -> str | None:
        return self.headers.get("server")

    def detect(self) -> list[dict[str, str]]:
        technologies = []

        html_lower = self.html.lower()

        signatures = {
            "WordPress": [
                "wp-content",
                "wp-includes",
            ],
            "Drupal": [
                "drupal-settings-json",
                "/sites/default/",
            ],
            "Joomla": [
                "/media/system/js/",
                "joomla",
            ],
            "React": [
                "__react",
                "react-dom",
            ],
            "Next.js": [
                "__next_data__",
                "/_next/",
            ],
            "Vue.js": [
                "__vue__",
                "vue.js",
            ],
            "Angular": [
                "ng-version",
                "angular.js",
            ],
            "jQuery": [
                "jquery",
            ],
            "Bootstrap": [
                "bootstrap.css",
                "bootstrap.min.css",
            ],
        }

        for technology, indicators in signatures.items():
            for indicator in indicators:
                if indicator.lower() in html_lower:
                    technologies.append(
                        {
                            "name": technology,
                            "evidence": indicator,
                        }
                    )

                    break

        generator = self._meta_generator()

        if generator:
            technologies.append(
                {
                    "name": "CMS Generator",
                    "evidence": generator,
                }
            )

        return technologies

    def _meta_generator(self) -> str | None:
        pattern = (
            r'<meta[^>]+name=["\']generator'
            r'["\'][^>]+content=["\']([^"\']+)'
        )

        match = re.search(
            pattern,
            self.html,
            flags=re.IGNORECASE,
        )

        if match:
            return match.group(1)

        return None

    def javascript_files(self) -> list[str]:
        pattern = (
            r'<script[^>]+src=["\']([^"\']+)'
        )

        return re.findall(
            pattern,
            self.html,
            flags=re.IGNORECASE,
        )

    def scan(self) -> dict:
        return {
            "server": self.detect_server(),
            "technologies": self.detect(),
            "javascript_files": self.javascript_files(),
        }