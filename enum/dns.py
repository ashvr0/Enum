from __future__ import annotations

from dataclasses import asdict, dataclass

import dns.exception
import dns.resolver


@dataclass
class DNSResult:
    target: str
    records: dict[str, list[str]]
    errors: dict[str, str]


class DNSScanner:
    RECORD_TYPES = (
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
    )

    def __init__(
        self,
        target: str,
        timeout: float = 3.0,
    ):
        self.target = self._clean_target(target)
        self.timeout = timeout

        self.resolver = dns.resolver.Resolver()

        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    @staticmethod
    def _clean_target(target: str) -> str:
        target = target.strip()

        target = target.removeprefix("https://")
        target = target.removeprefix("http://")

        target = target.split("/")[0]

        if ":" in target:
            target = target.split(":")[0]

        return target.rstrip(".")

    def query(self, record_type: str) -> list[str]:
        try:
            answers = self.resolver.resolve(
                self.target,
                record_type,
            )

            results = []

            for answer in answers:
                if record_type == "MX":
                    results.append(
                        f"{answer.preference} {answer.exchange}"
                    )

                elif record_type == "TXT":
                    text_parts = [
                        part.decode(
                            "utf8",
                            errors="replace",
                        )
                        for part in answer.strings
                    ]

                    results.append(
                        "".join(text_parts)
                    )

                elif record_type == "CNAME":
                    results.append(
                        str(answer.target)
                    )

                else:
                    results.append(
                        str(answer)
                    )

            return results

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
        ):
            return []

        except dns.exception.Timeout:
            raise RuntimeError(
                "DNS query timed out."
            )

        except dns.exception.DNSException as exc:
            raise RuntimeError(str(exc))

    def scan(self) -> DNSResult:
        records = {}
        errors = {}

        for record_type in self.RECORD_TYPES:
            try:
                records[record_type] = self.query(
                    record_type
                )

            except RuntimeError as exc:
                records[record_type] = []
                errors[record_type] = str(exc)

        return DNSResult(
            target=self.target,
            records=records,
            errors=errors,
        )

    def scan_dict(self) -> dict:
        return asdict(self.scan())