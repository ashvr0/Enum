from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from urllib.parse import urljoin

import requests


DEFAULT_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/favicon.ico",
    "/.git/",
    "/.env",
    "/admin/",
    "/login/",
    "/dashboard/",
    "/api/",
    "/docs/",
    "/uploads/",
    "/files/",
    "/backup/",
    "/backups/",
    "/test/",
    "/dev/",
    "/staging/",
]


@dataclass
class PathResult:
    path: str
    url: str
    status_code: int | None
    content_length: int
    content_type: str | None
    redirect: str | None
    error: str | None = None


class HTTPEnumerator:
    def __init__(
        self,
        base_url: str,
        timeout: float = 8.0,
        workers: int = 5,
        verify_tls: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.workers = max(1, min(workers, 10))
        self.verify_tls = verify_tls

        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": "Enum/0.1.0",
                "Accept": "*/*",
            }
        )

    def check_path(self, path: str) -> PathResult:
        url = urljoin(
            f"{self.base_url}/",
            path.lstrip("/"),
        )

        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_tls,
            )

            return PathResult(
                path=path,
                url=url,
                status_code=response.status_code,
                content_length=len(response.content),
                content_type=response.headers.get(
                    "Content-Type"
                ),
                redirect=response.headers.get(
                    "Location"
                ),
            )

        except requests.RequestException as exc:
            return PathResult(
                path=path,
                url=url,
                status_code=None,
                content_length=0,
                content_type=None,
                redirect=None,
                error=str(exc),
            )

    def scan(
        self,
        paths: list[str] | None = None,
    ) -> list[dict]:
        paths = paths or DEFAULT_PATHS

        results = []

        with ThreadPoolExecutor(
            max_workers=self.workers
        ) as executor:

            futures = [
                executor.submit(
                    self.check_path,
                    path,
                )
                for path in paths
            ]

            for future in futures:
                result = future.result()

                if result.status_code is not None:
                    results.append(asdict(result))

        return results