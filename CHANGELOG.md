# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [2.1.0] — 2026-06-03

### Added
- **`core/verifier.py`** — RCE verification module:
  - `check_real_rce()`: echo-marker test + known-output indicators (whoami, id, pwd, uname).
  - `blind_rce_test()`: time-delay (sleep 3 vs baseline) + DNS/OAST callback probes.
  - `_strict_verify_execution()`: 2-marker replay with baseline control (high-confidence confirmation).
- **`core/evasion_runner.py`** — Aggressive WAF bypass runner:
  - `aggressive_waf_bypass()`: 9 WAF techniques × 6 HTTP methods (POST/GET/PUT/PATCH/DELETE/OPTIONS).
  - Adds `X-Real-IP`, `CF-Connecting-IP`, `Referer` to each request for header-based bypass.
  - `find_working_endpoint()`: quick 30-endpoint probe to identify live API surfaces.
- **`core/exploiter.py`** — Extended exploit engine:
  - `exploit_vulnerability()`: 4-shell-form command fallback (`sh -c`, `/bin/sh -c`, `cmd /c`, bare), strict 2-marker verification, HTML false-positive detection.
  - `find_working_endpoint()` convenience re-export.
- **`core/report_loader.py`** — Interactive exploitation from JSON reports:
  - `load_report_and_exploit()`: loads report, filters confirmed/unverified findings.
  - `interactive_exploitation_menu()`: numbered target selection TUI.
  - `exploitation_command_menu()`: preset + custom command picker.
- **`core/reporter.py`** — Extended reporting:
  - `evaluate_finding_strictness()`: normalises legacy findings to `{status, confidence, reason_code}`.
  - `build_siem_schema_report()`: SIEM-compatible envelope (`schema_version`, `schema_type`, `scan_mode`).
  - `write_txt_report()`: human-readable TXT format.
  - `write_dual_report()`: atomic `.json` + `.txt` output.
- **`react2shell/scanner.py`** — Full React2Shell scanner:
  - 3 probe scenarios: `standard`, `safe-check`, `vercel-bypass`.
  - `_build_react2shell_body()`: multipart/form-data payload builder with padding and Vercel V0 prefix.
- **`audit/safe_audit.py`** — Expanded passive auditing:
  - `safe_encoding_audit()`: 5 marker variants (plain, URL, double-URL, base64, unicode) via GET + POST.
  - `safe_dependency_audit()`: library version leakage via `/actuator/env`, `/v2/api-docs`, swagger.
  - `safe_full_audit()`: unified audit → `overall_risk` (high/medium/low) with SIEM schema.
- **`audit/log_audit.py`** — Precise Log4Shell analysis:
  - `_parse_log4j_versions()`: regex extraction of Log4j version strings.
  - `_is_log4j_vulnerable()`: range check for CVE-2021-44228 (2.0.0 – 2.15.0).
  - `safe_log_audit()`: rich audit dict with `risk`, `versions_detected`, `evidence`.
- **CLI sub-commands**:
  - `spring2shell verify <url>`: echo-marker + blind RCE verification.
  - `spring2shell exploit <report.json>`: interactive exploitation from JSON report.
  - `spring2shell menu`: 13-item interactive TUI menu (matches legacy monolith).
- **CLI flags**:
  - `direct --no-strict-verify`: disable 2-marker verification.
  - `direct --quick`: limit to 6 common endpoints.
  - `direct --hybrid`: use CVE + generic payloads simultaneously.
  - `direct --find-endpoints`: auto-detect working endpoints before exploiting.
  - `cve-scan -t N / --threads N`: worker thread count.
- **Unit tests**: 163/163 passing; coverage 43% (up from 16%).
  - `tests/unit/test_verifier.py`, `test_evasion_runner.py`, `test_reporter.py`.
  - `tests/unit/test_safe_audit.py`, `test_log_audit.py`.
  - `tests/unit/test_report_loader.py`, `test_react2shell_scanner.py`.
- **Docker image**: `spring2shell:2.1.0` — non-root user, `dnsutils` for OOB tests, VOLUME `/app/reports`.

---

## [2.0.0] — 2026-06-02

### Added
- **src-layout package structure** (`src/spring2shell/`) — PEP 517/518 compliant.
- **Modular architecture**: `core/`, `discovery/`, `evasion/`, `audit/`, `react2shell/`, `utils/` sub-packages.
- **External data files**: CVE payloads, WAF bypasses, endpoints, and user-agents moved to `data/` directory (JSON/TXT).
- **YAML config system**: runtime profiles (`default`, `aggressive`, `safe_audit`, `stealth`) in `configs/`.
- **`pyproject.toml`**: replaces ad-hoc `requirements.txt`; defines dependencies, entry point, ruff/mypy/pytest config.
- **`Makefile`**: `make install-dev`, `make lint`, `make test`, `make run`, `make clean`.
- **`python -m spring2shell`** entry point via `__main__.py`.
- **CI/CD workflows**: `.github/workflows/lint.yml` and `test.yml`.
- **Unit tests scaffold**: `tests/unit/` with initial test modules for WAF engine, payload mutation, fingerprinting.
- **Documentation**: `docs/architecture.md`, `docs/cve_coverage.md`, `docs/legal_disclaimer.md`.
- **`.env.example`** template for runtime secrets/config overrides.
- **React2Shell module**: isolated sub-package `src/spring2shell/react2shell/`.

### Changed
- Monolithic `spring2shell.py` (3313 lines) refactored into 18+ focused modules.
- Payload constants (`CVE_PAYLOADS`, `PAYLOADS`, `EXPLOIT_PAYLOADS`, `WAF_BYPASSES`) externalized to `data/payloads/*.json`.
- Endpoint lists (`ENDPOINTS`, `CVE_ENDPOINTS`) moved to `data/endpoints/*.txt`.
- `USER_AGENTS` list moved to `data/useragents/user_agents.txt`.
- Runtime profiles (`RETRY_PROFILES`, `TIMEOUT_PROFILES`) moved to `configs/default.yaml`.

### Deprecated
- Direct invocation of `spring2shell.py` as a script — use `python -m spring2shell` or `spring2shell` CLI instead.

### Security
- `reports/` directory added to `.gitignore` to prevent accidental commit of scan output.
- `SSL_VERIFY = True` enforced as default; `--insecure` flag explicitly required to disable.
- `.env.example` documents all runtime-configurable security parameters.

---

## [1.0.0] — 2026-06-01

### Added
- Initial monolithic implementation with CVE-2025-55182, CVE-2025-66478, Log4Shell, Spring4Shell, Text4Shell payloads.
- Multi-mode CLI: `scan`, `exploit`, `direct`, `cve-scan`, `menu`, `safe-audit`, `log-audit`.
- WAF evasion engine with 9 bypass techniques.
- Endpoint discovery: sitemap parsing, JS analysis, subdomain enumeration.
- Tech fingerprinting and endpoint prioritization.
- React2Shell detection module.
- Structured JSON reporting with confidence, reason codes, and strict status semantics.
- `--insecure` / `--verbose-errors` global runtime flags.
- TLS-aware retry profiles (`default`, `safe-audit`, `aggressive`).

[Unreleased]: https://github.com/example/spring2shell/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/example/spring2shell/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/example/spring2shell/releases/tag/v1.0.0
