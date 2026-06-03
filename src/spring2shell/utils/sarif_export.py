"""
SARIF v2.1.0 JSON exporter for spring2shell.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def export_to_sarif(findings: list[dict[str, Any]], output_path: str | Path) -> Path:
    """Export findings as a standardized SARIF v2.1.0 JSON report.

    Args:
        findings:    List of finding dicts.
        output_path: Target path to write JSON.

    Returns:
        Path of written report.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    rules: dict[str, dict[str, Any]] = {}
    results = []

    for _idx, f in enumerate(findings):
        # Skip safe ones
        if f.get("status") == "not_vulnerable":
            continue

        cve = f.get("cve") or "generic-rce"
        rule_id = f"spring2shell-{cve.lower()}"

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {
                    "text": f.get("reason", "Vulnerability detected by spring2shell")
                },
                "fullDescription": {"text": f"Vulnerability {cve} detected on target endpoint."},
                "helpUri": f"https://nvd.nist.gov/vuln/detail/{cve}"
                if f.get("cve")
                else "https://github.com/PROJECTS/Spring2Shell-1",
            }

        level = "error" if f.get("status") == "confirmed" else "warning"

        result = {
            "ruleId": rule_id,
            "ruleIndex": list(rules.keys()).index(rule_id),
            "level": level,
            "message": {"text": f.get("evidence", "Potential Remote Code Execution.")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("endpoint", f.get("url", ""))}
                    }
                }
            ],
        }
        results.append(result)

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemadata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "spring2shell",
                        "semanticVersion": "3.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
    return path
