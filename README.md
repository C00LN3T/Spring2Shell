# React2Shell

React2Shell is a Python-based scanner and exploitation toolkit targeting React/Spring/GraphQL stacks. It mixes endpoint discovery, stealthy HTTP behavior, and payload mutation to exercise potentially vulnerable deployments, including routines tuned for the documented CVE-2025-55182 and CVE-2025-66478 vectors.

## Features
- Multi-mode CLI supporting bulk scanning, direct exploitation, CVE-focused sweeps, and an interactive menu.
- Endpoint discovery via sitemap parsing, JavaScript analysis, and curated actuator/GraphQL paths.
- WAF-evasion helpers that randomize headers, mutate payloads, and add jitter between requests.
- Protocol hopping (HTTP/HTTPS), tech fingerprinting, and subdomain probing to widen coverage.
- Built-in payload sets for command execution and CVE-specific exploitation attempts.
- Safe non-exploit audit family: encoding behavior, dependency leakage, misconfiguration, and Log2Shell/Log4Shell risk indicators.
- Structured SIEM/CI-ready JSON reporting with confidence, reason codes, and unverified status semantics.

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

Global runtime flags:
```bash
python cracker.py --insecure direct https://target.example
python cracker.py --verbose-errors safe-audit https://target.example
```
- `--insecure` disables TLS certificate verification (legacy behavior, not recommended for trusted audit results).
- `--verbose-errors` logs swallowed network exceptions to improve troubleshooting and explainability.

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
- Probes all known endpoints for the target. Add options such as `-e /api/graphql` to focus on one path, `-c "whoami"` to change the command, `--aggressive` to enable stronger WAF bypassing, or `--no-strict-verify` to disable strict replay verification.

- Findings now use strict statuses (`confirmed`, `unverified`, `not_vulnerable`) with confidence and reason codes in JSON reports.

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

### Safe encoding audit (no RCE payloads)
```bash
python cracker.py safe-audit https://target.example -o safe_audit.json
```
- Runs a full passive audit family (encoding + dependency leakage + misconfiguration + log risk) with strict aggregated risk summary, without executing commands.

### Safe Log2Shell/Log4Shell risk audit (no exploit payloads)
```bash
python cracker.py log-audit https://target.example -o log_audit.json
```
- Performs passive checks for exposed management endpoints and log4j version indicators to estimate Log2Shell/Log4Shell risk.

## Notes
- TLS certificate verification is enabled by default. Use `--insecure` only in controlled environments when needed.
- Use `--verbose-errors` if you need detailed diagnostics for swallowed network exceptions during discovery/audit phases.
- Commands are for educational and authorized testing purposes. Ensure you have permission before scanning or exploiting any target.
