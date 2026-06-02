# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
