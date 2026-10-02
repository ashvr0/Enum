# Enum
A Python tool for website reconnaissance and enumeration.
Enum scans websites for publicly accessible information useful during authorized security assessments and security research.

## Features
Enum can scan for:
* Subdomains
* DNS information
* HTTP information
* TLS information
* Web content and discovery
* Potentially exposed information
* Technology detection
* Reports

## Installation
Clone the repository and enter the project directory.

```bash
git clone 
cd Enum
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Linux:

```bash
source .venv/bin/activate
```

Install the required dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage
Run Enum against a target you are authorized to scan:
```bash
python -m enumtool.cli example.com
```

Generate a JSON report:
```bash
python -m enumtool.cli example.com --json report.json
```

Generate an HTML report:
```bash
python -m enumtool.cli example.com --html report.html
```

## Notes
If you encounter a problem with the project, please open an issue in the repository.

## License

This project is intended for authorized security testing and research only.

Only scan targets that you have explicit permission to assess. The author is not responsible for misuse of this tool or for any consequences resulting from unauthorized scanning.

This project is licensed under the GPLv3.0. See the `LICENSE` file for details.
