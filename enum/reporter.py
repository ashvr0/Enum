from __future__ import annotations

import html
import json
from pathlib import Path


class Reporter:
    def __init__(self, results: dict):
        self.results = results

    def terminal(self) -> str:
        output = []

        target = self.results.get(
            "target",
            "unknown",
        )

        output.append("")
        output.append(
            f"ENUMERATION REPORT: {target}"
        )
        output.append("=" * 60)

        self._section(
            output,
            "DNS",
            self.results.get("dns", {}),
        )

        self._section(
            output,
            "SUBDOMAINS",
            self.results.get("subdomains", []),
        )

        self._section(
            output,
            "HTTP",
            self.results.get("http", {}),
        )

        self._section(
            output,
            "TLS",
            self.results.get("tls", {}),
        )

        self._section(
            output,
            "WEB DISCOVERY",
            self.results.get("discovery", {}),
        )

        self._section(
            output,
            "TECHNOLOGY",
            self.results.get("technology", {}),
        )

        self._section(
            output,
            "EXPOSURE",
            self.results.get("exposure", []),
        )

        output.append("")
        output.append("=" * 60)
        output.append("Enumeration complete.")

        return "\n".join(output)

    @staticmethod
    def _section(
        output: list[str],
        title: str,
        data,
    ):
        output.append("")
        output.append(f"[{title}]")
        output.append("-" * 40)

        if not data:
            output.append("No data.")
            return

        if isinstance(data, dict):
            Reporter._print_dict(
                output,
                data,
            )

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    output.append(
                        json.dumps(
                            item,
                            indent=2,
                        )
                    )
                else:
                    output.append(str(item))

    @staticmethod
    def _print_dict(
        output: list[str],
        data: dict,
        indent: int = 0,
    ):
        prefix = " " * indent

        for key, value in data.items():
            if isinstance(value, dict):
                output.append(
                    f"{prefix}{key}:"
                )

                Reporter._print_dict(
                    output,
                    value,
                    indent + 2,
                )

            elif isinstance(value, list):
                output.append(
                    f"{prefix}{key}:"
                )

                for item in value:
                    output.append(
                        f"{prefix}  {item}"
                    )

            else:
                output.append(
                    f"{prefix}{key}: {value}"
                )

    def save_json(
        self,
        filename: str = "report.json",
    ) -> Path:
        path = Path(filename)

        path.write_text(
            json.dumps(
                self.results,
                indent=2,
                default=str,
            ),
            encoding="utf8",
        )

        return path

    def save_html(
        self,
        filename: str = "report.html",
    ) -> Path:
        path = Path(filename)

        target = html.escape(
            str(
                self.results.get(
                    "target",
                    "unknown",
                )
            )
        )

        data = html.escape(
            json.dumps(
                self.results,
                indent=2,
                default=str,
            )
        )

        document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0">
<title>Enum Report</title>

<style>
body {{
    font-family: monospace;
    background: #111;
    color: #eee;
    margin: 0;
    padding: 30px;
}}

main {{
    max-width: 1200px;
    margin: auto;
}}

h1 {{
    color: #c084fc;
}}

pre {{
    background: #1b1b1b;
    padding: 20px;
    border-radius: 8px;
    overflow-x: auto;
    white-space: pre-wrap;
}}
</style>
</head>

<body>
<main>
<h1>Enum Report</h1>

<p>
Target: {target}
</p>

<pre>{data}</pre>

</main>
</body>
</html>
"""

        path.write_text(
            document,
            encoding="utf8",
        )

        return path