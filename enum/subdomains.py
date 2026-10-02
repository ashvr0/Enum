from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass


DEFAULT_SUBDOMAINS = [
    "www",
    "api",
    "app",
    "dev",
    "test",
    "staging",
    "stage",
    "admin",
    "portal",
    "mail",
    "webmail",
    "blog",
    "docs",
    "support",
    "help",
    "status",
    "cdn",
    "static",
    "assets",
    "media",
    "files",
    "download",
    "uploads",
    "login",
    "auth",
    "accounts",
    "dashboard",
    "secure",
    "vpn",
    "git",
]


@dataclass
class SubdomainResult:
    subdomain: str
    addresses: list[str]


class SubdomainScanner:
    def __init__(
        self,
        domain: str,
        wordlist: list[str] | None = None,
        workers: int = 10,
    ):
        self.domain = self._clean_domain(domain)
        self.wordlist = wordlist or DEFAULT_SUBDOMAINS
        self.workers = max(1, min(workers, 20))

    @staticmethod
    def _clean_domain(domain: str) -> str:
        domain = domain.strip()

        domain = domain.removeprefix("https://")
        domain = domain.removeprefix("http://")

        return domain.split("/")[0].rstrip(".")

    def resolve(self, name: str) -> SubdomainResult | None:
        hostname = f"{name}.{self.domain}"

        try:
            addresses = sorted(
                {
                    address
                    for address in socket.getaddrinfo(
                        hostname,
                        None,
                        socket.AF_UNSPEC,
                    )
                    for address in [address[4][0]]
                }
            )

            if not addresses:
                return None

            return SubdomainResult(
                subdomain=hostname,
                addresses=addresses,
            )

        except socket.gaierror:
            return None

    def scan(self) -> list[dict]:
        results = []

        with ThreadPoolExecutor(
            max_workers=self.workers
        ) as executor:

            futures = [
                executor.submit(
                    self.resolve,
                    name,
                )
                for name in self.wordlist
            ]

            for future in futures:
                result = future.result()

                if result:
                    results.append(asdict(result))

        return sorted(
            results,
            key=lambda item: item["subdomain"],
        )