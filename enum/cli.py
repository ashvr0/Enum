from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

from .dns import DNSScanner
from .discovery import DiscoveryScanner
from .exposure import ExposureScanner
from .http import HTTPEnumerator
from .reporter import Reporter
from .scanner import Scanner
from .subdomains import SubdomainScanner
from .technology import TechnologyScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enum",
        description=(
            "Website reconnaissance and enumeration "
            "tool for authorized security testing."
        ),
    )

    parser.add_argument(
        "target",
        help="Target domain or URL",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Network timeout in seconds",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=5,
        help="Maximum concurrent requests",
    )

    parser.add_argument(
        "--no-tls-verify",
        action="store_true",
        help="Disable TLS certificate verification",
    )

    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save JSON report",
    )

    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save HTML report",
    )

    parser.add_argument(
        "--wordlist",
        metavar="FILE",
        help="Custom subdomain wordlist",
    )

    return parser


def clean_domain(target: str) -> str:
    value = target.strip()

    if not value.startswith(
        ("http://", "https://")
    ):
        value = f"https://{value}"

    parsed = urlparse(value)

    if not parsed.hostname:
        raise ValueError(
            f"Invalid target: {target}"
        )

    return parsed.hostname


def load_wordlist(
    filename: str | None,
) -> list[str] | None:
    if not filename:
        return None

    path = Path(filename)

    if not path.exists():
        raise FileNotFoundError(
            f"Wordlist not found: {filename}"
        )

    words = []

    for line in path.read_text(
        encoding="utf8",
        errors="ignore",
    ).splitlines():

        word = line.strip()

        if not word:
            continue

        if word.startswith("#"):
            continue

        words.append(word)

    return words


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        domain = clean_domain(
            args.target
        )

        wordlist = load_wordlist(
            args.wordlist
        )

        verify_tls = not args.no_tls_verify

        print("")
        print("Enum Website Reconnaissance")
        print("=" * 40)
        print(f"Target: {domain}")
        print("")

        print("[+] HTTP and TLS")

        scanner = Scanner(
            args.target,
            timeout=args.timeout,
            verify_tls=verify_tls,
        )

        core = scanner.scan()

        http_result = core["http"]

        base_url = http_result.get(
            "final_url"
        ) or core["target"]

        print("[+] DNS")

        dns_result = DNSScanner(
            domain,
            timeout=args.timeout,
        ).scan_dict()

        print("[+] Subdomains")

        subdomains = SubdomainScanner(
            domain,
            wordlist=wordlist,
            workers=args.workers,
        ).scan()

        print("[+] Web discovery")

        web_paths = HTTPEnumerator(
            base_url,
            timeout=args.timeout,
            workers=args.workers,
            verify_tls=verify_tls,
        ).scan()

        discovery = DiscoveryScanner(
            base_url,
            timeout=args.timeout,
            verify_tls=verify_tls,
        ).scan()

        print("[+] Technology detection")

        technology = TechnologyScanner(
            html=http_result.get(
                "body",
                "",
            ),
            headers=http_result.get(
                "headers",
                {},
            ),
        ).scan()

        print("[+] Exposure analysis")

        exposure = ExposureScanner(
            headers=http_result.get(
                "headers",
                {},
            ),
            cookies=http_result.get(
                "cookies",
                [],
            ),
            discovered_paths=web_paths,
        ).scan()

        results = {
            "target": core["target"],
            "dns": dns_result,
            "subdomains": subdomains,
            "http": {
                key: value
                for key, value in http_result.items()
                if key != "body"
            },
            "tls": core["tls"],
            "discovery": discovery,
            "web_paths": web_paths,
            "technology": technology,
            "exposure": exposure,
        }

        reporter = Reporter(results)

        print(
            reporter.terminal()
        )

        if args.json:
            path = reporter.save_json(
                args.json
            )

            print(
                f"\n[+] JSON report: {path}"
            )

        if args.html:
            path = reporter.save_html(
                args.html
            )

            print(
                f"[+] HTML report: {path}"
            )

        return 0

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.")
        return 130

    except Exception as exc:
        print(
            f"[!] Error: {exc}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())