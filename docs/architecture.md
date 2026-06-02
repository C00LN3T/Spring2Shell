# Architecture — spring2shell v2.0.0

## Overview

spring2shell is a Python-based CVE scanner and exploitation toolkit targeting
Spring/GraphQL/React stacks. The v2.0 refactor adopts a **src-layout package**
architecture with strict separation between data, configuration, and logic.

---

## Package Layout

```
src/spring2shell/
├── cli.py              ← argparse entry point
├── core/               ← scan loop, exploitation, reporting, session
├── discovery/          ← endpoint wordlists, fingerprinting, JS/sitemap
├── evasion/            ← WAF engine, header randomisation, payload mutations
├── audit/              ← passive-only safe-audit and log-audit modes
├── react2shell/        ← React Server Components exploitation detection
└── utils/              ← logging, network config, signal handling
```

## Data Flow

```
CLI args
  │
  ▼
cli.py (argument parsing + configure_runtime())
  │
  ├─► discovery/endpoints.py  ── data/endpoints/*.txt
  ├─► discovery/fingerprint.py
  ├─► discovery/sitemap.py
  ├─► discovery/js_analyzer.py
  │
  ├─► evasion/waf_engine.py   ── data/payloads/waf_bypasses.json
  ├─► evasion/headers.py      ── data/useragents/user_agents.txt
  ├─► evasion/mutations.py
  │
  ├─► core/session.py         ── configs/default.yaml + profiles/
  ├─► core/scanner.py
  ├─► core/exploiter.py       ── data/payloads/cve_payloads.json
  │
  └─► core/reporter.py        ── reports/*.json
```

## Key Design Decisions

| Decision | Rationale |
|---|---|
| **src-layout** | Prevents bare `import spring2shell` without installation; matches OpenAI/Anthropic standards |
| **Data externalization** | Payload databases in JSON/TXT — updatable without code changes (Kaspersky TI practice) |
| **YAML config profiles** | Composable runtime profiles for different scan modes (Palantir style) |
| **Modular sub-packages** | Each concern isolated: discovery, evasion, audit, react2shell |
| **Structured reporter** | `build_finding()` enforces schema; enables SIEM/CI integration |
| **Lazy imports in CLI** | Sub-command imports deferred — `--insecure` takes effect before any network code runs |

## Dependency Graph (internal)

```
cli.py
  └── utils/network, utils/signals
      core/scanner, core/exploiter
        └── core/session ← utils/network
            evasion/waf_engine, evasion/headers, evasion/mutations
              └── utils/logging
            discovery/endpoints ← data/endpoints/*.txt
              discovery/sitemap, discovery/js_analyzer ← utils/network
            core/reporter
```

## Adding a New CVE Module

1. Add payloads to `data/payloads/cve_payloads.json` under a new CVE key.
2. Add targeted endpoints to `data/endpoints/cve_endpoints.txt`.
3. If a dedicated scan mode is needed, create `src/spring2shell/core/cve_<name>.py`.
4. Register a sub-command in `cli.py`.
5. Add unit tests in `tests/unit/`.
