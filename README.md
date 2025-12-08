# React2Shell

React2Shell is a Python-based scanner and exploitation toolkit targeting React/Spring/GraphQL stacks. It mixes endpoint discovery, stealthy HTTP behavior, and payload mutation to exercise potentially vulnerable deployments, including routines tuned for the documented CVE-2025-55182 and CVE-2025-66478 vectors.

## Features
- Multi-mode CLI supporting bulk scanning, direct exploitation, CVE-focused sweeps, and an interactive menu.
- Endpoint discovery via sitemap parsing, JavaScript analysis, and curated actuator/GraphQL paths.
- WAF-evasion helpers that randomize headers, mutate payloads, and add jitter between requests.
- Protocol hopping (HTTP/HTTPS), tech fingerprinting, and subdomain probing to widen coverage.
- Built-in payload sets for command execution and CVE-specific exploitation attempts.

## Requirements
- Python 3.8+
- Dependencies: `requests`, `urllib3` (others in the standard library)

Install the dependencies with:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests urllib3
```

## Usage
Display the built-in help:
```bash
python cracker.py -h
```

### Scan a list of targets
```bash
python cracker.py scan targets.txt reports/prefix
```
- Reads URLs from `targets.txt` and writes JSON reports using the given prefix.

### Exploit from a saved report
```bash
python cracker.py exploit reports/prefix.json
```
- Loads a previously generated report and reruns exploitation attempts.

### Direct exploitation
```bash
python cracker.py direct https://target.example --test-all
```
- Probes all known endpoints for the target. Add options such as `-e /api/graphql` to focus on one path, `-c "whoami"` to change the command, or `--aggressive` to enable stronger WAF bypassing.

### CVE-focused mass scan
```bash
python cracker.py cve-scan targets.txt -o cve_results.txt
```
- Runs payloads tailored to CVE-2025-55182 and CVE-2025-66478 across the provided targets.

### Interactive menu
```bash
python cracker.py menu
```
- Launches an interactive workflow for discovery, exploitation, and persistence checks.

## Notes
- The tool intentionally disables certificate verification for convenience; use it only in controlled environments.
- Commands are for educational and authorized testing purposes. Ensure you have permission before scanning or exploiting any target.
