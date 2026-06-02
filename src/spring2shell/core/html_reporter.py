"""
HTML report generator for spring2shell.

Produces a self-contained Bootstrap 5 + Chart.js report from scan findings.
Color coding: confirmed=red, unverified=yellow, not_vulnerable=green.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Remediation recommendations
# ---------------------------------------------------------------------------

_REMEDIATIONS: dict[str, str] = {
    "CVE-2025-55182": "Upgrade Spring Framework to 6.1.x or 5.3.x latest. Disable SpEL evaluation in user-controlled input.",
    "CVE-2025-66478": "Restrict GraphQL query depth and disable field suggestions in production.",
    "CVE-2021-44228": "Upgrade Log4j to 2.17.1+. Set JVM flag -Dlog4j2.formatMsgNoLookups=true.",
    "CVE-2022-22965": "Upgrade Spring Framework to 5.3.18+ or 5.2.20+. Disable class-based data binding.",
    "CVE-2022-42889": "Upgrade Apache Commons Text to 1.10.0+.",
    "CVE-2023-46604": "Upgrade Apache ActiveMQ to 5.15.16+, 5.16.7+, 5.17.6+, or 5.18.3+. Restrict ActiveMQ admin access.",
    "CVE-2024-22243": "Upgrade Spring Framework to 5.3.32+, 6.0.17+, or 6.1.4+. Validate URLs before processing.",
    "CVE-2024-38816": "Upgrade Spring Framework to 5.3.40+, 6.0.24+, or 6.1.12+. Use PathMatchingResourcePatternResolver with allowedPaths.",
    "CVE-2024-4577": "Upgrade PHP to 8.1.29+, 8.2.20+, or 8.3.8+. Disable CGI handler if not needed.",
    "CVE-2023-34104": "Upgrade fast-xml-parser to 4.2.4+. Disable entity expansion.",
    "CVE-2024-21626": "Upgrade runc to 1.1.12+. Avoid exposing /proc/self/fd in containers.",
}

_DEFAULT_REMEDIATION = "Review vendor security advisories and apply the latest security patches."


def _severity_class(status: str, confidence: str) -> str:
    """Return Bootstrap badge class based on finding status/confidence."""
    if status == "confirmed":
        return "danger"
    if status == "unverified" and confidence == "high":
        return "warning"
    if status == "unverified":
        return "warning"
    return "success"


def _severity_label(status: str) -> str:
    return {"confirmed": "CONFIRMED", "unverified": "POTENTIAL", "not_vulnerable": "SAFE"}.get(
        status, status.upper()
    )


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>spring2shell — Scan Report</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet" crossorigin="anonymous">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"
          crossorigin="anonymous"></script>
  <style>
    body {{ background: #0d1117; color: #e6edf3; font-family: 'Segoe UI', sans-serif; }}
    .navbar-brand {{ font-weight: 700; letter-spacing: 1px; }}
    .card {{ background: #161b22; border: 1px solid #30363d; }}
    .card-header {{ background: #21262d; border-bottom: 1px solid #30363d; }}
    .finding-confirmed {{ border-left: 4px solid #f85149; }}
    .finding-unverified {{ border-left: 4px solid #e3b341; }}
    .finding-safe {{ border-left: 4px solid #3fb950; }}
    .badge-danger {{ background-color: #f85149; }}
    .code-block {{
      background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
      padding: 12px; font-family: monospace; font-size: 0.82rem;
      white-space: pre-wrap; word-break: break-all; color: #7ee787;
    }}
    .stat-number {{ font-size: 2.5rem; font-weight: 700; }}
    footer {{ border-top: 1px solid #30363d; }}
  </style>
</head>
<body>

<nav class="navbar navbar-dark" style="background:#21262d; border-bottom:1px solid #30363d;">
  <div class="container-fluid">
    <span class="navbar-brand">🛡 spring2shell</span>
    <span class="text-secondary small">Scan Report — {generated_at}</span>
  </div>
</nav>

<div class="container-fluid py-4">

  <!-- Summary stats -->
  <div class="row g-3 mb-4">
    <div class="col-md-3">
      <div class="card text-center p-3">
        <div class="stat-number text-danger">{confirmed_count}</div>
        <div class="text-secondary">Confirmed RCE</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card text-center p-3">
        <div class="stat-number text-warning">{unverified_count}</div>
        <div class="text-secondary">Potential</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card text-center p-3">
        <div class="stat-number text-success">{safe_count}</div>
        <div class="text-secondary">Not Vulnerable</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card text-center p-3">
        <div class="stat-number text-info">{total_count}</div>
        <div class="text-secondary">Total Findings</div>
      </div>
    </div>
  </div>

  <!-- Chart + CVE breakdown -->
  <div class="row g-3 mb-4">
    <div class="col-md-5">
      <div class="card p-3 h-100">
        <div class="card-header mb-3">Finding Distribution</div>
        <canvas id="donutChart" style="max-height:280px;"></canvas>
      </div>
    </div>
    <div class="col-md-7">
      <div class="card p-3 h-100">
        <div class="card-header mb-3">CVE Coverage</div>
        <canvas id="barChart" style="max-height:280px;"></canvas>
      </div>
    </div>
  </div>

  <!-- Findings table -->
  <div class="card mb-4">
    <div class="card-header">All Findings ({total_count})</div>
    <div class="p-3">
      <table class="table table-dark table-hover table-sm">
        <thead>
          <tr>
            <th>Status</th><th>URL</th><th>CVE</th><th>Confidence</th><th>Method</th><th>Time</th>
          </tr>
        </thead>
        <tbody>
          {table_rows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Finding details -->
  <h5 class="mb-3">Finding Details</h5>
  {finding_cards}

</div>

<footer class="text-center text-secondary py-3 small">
  Generated by spring2shell &bull; For authorized security testing only
</footer>

<script>
const donutCtx = document.getElementById('donutChart').getContext('2d');
new Chart(donutCtx, {{
  type: 'doughnut',
  data: {{
    labels: ['Confirmed', 'Potential', 'Safe'],
    datasets: [{{
      data: [{confirmed_count}, {unverified_count}, {safe_count}],
      backgroundColor: ['#f85149', '#e3b341', '#3fb950'],
      borderWidth: 0,
    }}]
  }},
  options: {{ plugins: {{ legend: {{ labels: {{ color: '#e6edf3' }} }} }} }}
}});

const barCtx = document.getElementById('barChart').getContext('2d');
new Chart(barCtx, {{
  type: 'bar',
  data: {{
    labels: {cve_labels},
    datasets: [{{
      label: 'Findings per CVE',
      data: {cve_counts},
      backgroundColor: '#1f6feb',
      borderRadius: 4,
    }}]
  }},
  options: {{
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }},
      y: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }}, beginAtZero: true }}
    }}
  }}
}});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def generate_html_report(
    findings: list[dict[str, Any]],
    output_path: str | Path,
) -> Path:
    """Generate a self-contained HTML scan report.

    Args:
        findings:    List of finding dicts (from :func:`~spring2shell.core.reporter.build_finding`).
        output_path: Destination file path (e.g. ``reports/scan_result.html``).

    Returns:
        Resolved :class:`~pathlib.Path` of the written file.
    """
    path = Path(output_path)
    if path.suffix.lower() != ".html":
        path = path.with_suffix(".html")
    path.parent.mkdir(parents=True, exist_ok=True)

    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    unverified = [f for f in findings if f.get("status") == "unverified"]
    safe = [f for f in findings if f.get("status") not in ("confirmed", "unverified")]
    total = len(findings)

    # CVE bar chart data
    cve_counter: dict[str, int] = {}
    for f in findings:
        cve = f.get("cve") or "Unknown"
        cve_counter[cve] = cve_counter.get(cve, 0) + 1
    cve_labels = json.dumps(list(cve_counter.keys()))
    cve_counts = json.dumps(list(cve_counter.values()))

    # Table rows
    rows_html = ""
    for f in sorted(findings, key=lambda x: {"confirmed": 0, "unverified": 1}.get(x.get("status", ""), 2)):
        sclass = _severity_class(f.get("status", ""), f.get("confidence", ""))
        label = _severity_label(f.get("status", ""))
        ep = f.get("endpoint") or f.get("url", "N/A")
        cve = f.get("cve", "—")
        conf = f.get("confidence", "—")
        method = f.get("method", "—")
        ts = f.get("timestamp", "")[:19].replace("T", " ")
        rows_html += (
            f'<tr><td><span class="badge bg-{sclass}">{label}</span></td>'
            f'<td class="small text-truncate" style="max-width:300px;" title="{ep}">{ep}</td>'
            f'<td><code>{cve}</code></td><td>{conf}</td><td>{method}</td><td>{ts}</td></tr>\n'
        )

    # Finding cards
    cards_html = ""
    for i, f in enumerate(findings, 1):
        sclass = _severity_class(f.get("status", ""), f.get("confidence", ""))
        label = _severity_label(f.get("status", ""))
        ep = f.get("endpoint") or f.get("url", "N/A")
        cve = f.get("cve", "")
        remediation = _REMEDIATIONS.get(cve, _DEFAULT_REMEDIATION) if cve else _DEFAULT_REMEDIATION
        border_class = f"finding-{f.get('status', 'safe')}"
        cards_html += f"""
<div class="card mb-3 {border_class}">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span>
      <span class="badge bg-{sclass} me-2">{label}</span>
      <strong>#{i}</strong> — <code class="ms-1">{ep}</code>
    </span>
    {"<span class='badge bg-secondary'>" + cve + "</span>" if cve else ""}
  </div>
  <div class="card-body">
    <dl class="row mb-0">
      <dt class="col-sm-2">Target URL</dt>
      <dd class="col-sm-10"><code>{f.get('url', 'N/A')}</code></dd>
      <dt class="col-sm-2">Confidence</dt>
      <dd class="col-sm-10">{f.get('confidence', '—')}</dd>
      <dt class="col-sm-2">Reason</dt>
      <dd class="col-sm-10">{f.get('reason', '—')}</dd>
      <dt class="col-sm-2">Evidence</dt>
      <dd class="col-sm-10">{f.get('evidence', '—')}</dd>
      {"<dt class='col-sm-2'>Payload</dt><dd class='col-sm-10'><div class='code-block'>" + (f.get('payload') or '') + "</div></dd>" if f.get('payload') else ""}
      <dt class="col-sm-2">Remediation</dt>
      <dd class="col-sm-10 text-warning">{remediation}</dd>
    </dl>
  </div>
</div>
"""

    if not findings:
        cards_html = '<div class="alert alert-success">No findings detected.</div>'

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html = _HTML_TEMPLATE.format(
        generated_at=generated_at,
        confirmed_count=len(confirmed),
        unverified_count=len(unverified),
        safe_count=len(safe),
        total_count=total,
        cve_labels=cve_labels,
        cve_counts=cve_counts,
        table_rows=rows_html,
        finding_cards=cards_html,
    )

    path.write_text(html, encoding="utf-8")
    return path
