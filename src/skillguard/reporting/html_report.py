"""HTML report generator using Jinja2 templates.

Generates rich, self-contained HTML reports from scan results that
can be viewed in any browser and shared as standalone files.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from jinja2 import Environment, BaseLoader

from skillguard.core.models import ScanResult, Severity


_VERDICT_COLORS: dict[str, str] = {
    "clean": "#22c55e",
    "low_risk": "#06b6d4",
    "suspicious": "#eab308",
    "high_risk": "#ef4444",
    "malicious": "#dc2626",
}

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#ef4444",
    "medium": "#eab308",
    "low": "#06b6d4",
    "info": "#9ca3af",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SkillGuard Scan Report - {{ result.skill_name }}</title>
<style>
  :root {
    --bg: #0f172a;
    --surface: #1e293b;
    --border: #334155;
    --text: #e2e8f0;
    --text-dim: #94a3b8;
    --accent: #3b82f6;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
  }
  h1, h2, h3 { margin-bottom: 0.5rem; }
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border);
  }
  .header h1 { color: var(--accent); font-size: 1.5rem; }
  .header .meta { color: var(--text-dim); font-size: 0.85rem; }
  .verdict-card {
    background: var(--surface);
    border-radius: 12px;
    padding: 2rem;
    margin-bottom: 1.5rem;
    border-left: 4px solid {{ verdict_color }};
  }
  .verdict-badge {
    display: inline-block;
    padding: 0.25rem 1rem;
    border-radius: 6px;
    font-weight: bold;
    font-size: 1.2rem;
    color: white;
    background: {{ verdict_color }};
  }
  .score-bar {
    background: var(--border);
    border-radius: 8px;
    height: 12px;
    margin: 1rem 0;
    overflow: hidden;
  }
  .score-fill {
    height: 100%;
    border-radius: 8px;
    background: {{ verdict_color }};
    width: {{ result.composite_score }}%;
    transition: width 0.5s ease;
  }
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
    margin: 1.5rem 0;
  }
  .stat-card {
    background: var(--surface);
    border-radius: 8px;
    padding: 1rem;
    text-align: center;
  }
  .stat-card .value { font-size: 2rem; font-weight: bold; color: var(--accent); }
  .stat-card .label { font-size: 0.8rem; color: var(--text-dim); }
  .engine-table, .findings-table {
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
  }
  .engine-table th, .findings-table th {
    background: var(--surface);
    padding: 0.75rem 1rem;
    text-align: left;
    font-size: 0.85rem;
    color: var(--text-dim);
    border-bottom: 1px solid var(--border);
  }
  .engine-table td, .findings-table td {
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.9rem;
  }
  .severity-badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: bold;
    color: white;
  }
  .verdict-clean { color: #22c55e; }
  .verdict-suspicious { color: #eab308; }
  .verdict-malicious { color: #ef4444; }
  .section {
    background: var(--surface);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .section h2 { color: var(--accent); margin-bottom: 1rem; font-size: 1.1rem; }
  .snippet {
    background: #0f172a;
    border-radius: 6px;
    padding: 0.5rem;
    font-family: 'Fira Code', 'Cascadia Code', monospace;
    font-size: 0.8rem;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 100px;
    overflow-y: auto;
    color: var(--text-dim);
  }
  .footer {
    text-align: center;
    margin-top: 2rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--text-dim);
    font-size: 0.8rem;
  }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>SkillGuard Scan Report</h1>
    <div class="meta">Generated {{ generated_at }}</div>
  </div>
  <div style="text-align: right;">
    <div class="meta">Scan ID: {{ result.scan_id }}</div>
    <div class="meta">SHA256: {{ result.skill_sha256[:16] }}...</div>
  </div>
</div>

<div class="verdict-card">
  <div style="display: flex; justify-content: space-between; align-items: center;">
    <div>
      <h2>{{ result.skill_name }}</h2>
      <div style="margin-top: 0.5rem;">
        <span class="verdict-badge">{{ verdict_label }}</span>
        <span style="margin-left: 1rem; font-size: 1.5rem; font-weight: bold;">{{ result.composite_score }}/100</span>
      </div>
    </div>
  </div>
  <div class="score-bar"><div class="score-fill"></div></div>
</div>

<div class="stats-grid">
  <div class="stat-card">
    <div class="value">{{ result.files_scanned }}</div>
    <div class="label">Files Scanned</div>
  </div>
  <div class="stat-card">
    <div class="value">{{ result.engine_results|length }}</div>
    <div class="label">Engines</div>
  </div>
  <div class="stat-card">
    <div class="value">{{ result.total_findings }}</div>
    <div class="label">Total Findings</div>
  </div>
  <div class="stat-card">
    <div class="value">{{ critical_count }}</div>
    <div class="label">Critical</div>
  </div>
</div>

{% if result.engine_results %}
<div class="section">
  <h2>Engine Results</h2>
  <table class="engine-table">
    <thead>
      <tr><th>Engine</th><th>Verdict</th><th>Confidence</th><th>Findings</th><th>Time (ms)</th></tr>
    </thead>
    <tbody>
    {% for er in result.engine_results %}
      <tr>
        <td>{{ er.engine_name }}</td>
        <td class="verdict-{{ er.verdict if er.verdict is string else er.verdict.value }}">
          {{ (er.verdict if er.verdict is string else er.verdict.value)|upper }}
        </td>
        <td>{{ "%.0f"|format(er.confidence * 100) }}%</td>
        <td>{{ er.findings|length }}</td>
        <td>{{ er.duration_ms }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

{% if all_findings %}
<div class="section">
  <h2>Findings Detail ({{ all_findings|length }})</h2>
  <table class="findings-table">
    <thead>
      <tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Description</th></tr>
    </thead>
    <tbody>
    {% for f in all_findings[:100] %}
      <tr>
        <td>
          <span class="severity-badge" style="background: {{ severity_colors[f.severity if f.severity is string else f.severity.value] }}">
            {{ (f.severity if f.severity is string else f.severity.value)|upper }}
          </span>
        </td>
        <td>{{ f.rule_id }}</td>
        <td>{{ f.file_path }}</td>
        <td>{{ f.line_start or '' }}</td>
        <td>
          {{ f.description[:120] }}{% if f.description|length > 120 %}...{% endif %}
          {% if f.snippet %}
          <div class="snippet">{{ f.snippet[:200] }}</div>
          {% endif %}
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% if all_findings|length > 100 %}
  <p style="color: var(--text-dim); margin-top: 0.5rem;">
    Showing first 100 of {{ all_findings|length }} findings.
  </p>
  {% endif %}
</div>
{% endif %}

{% if result.owasp_coverage %}
<div class="section">
  <h2>OWASP LLM Top 10 Coverage</h2>
  <p>{{ result.owasp_coverage|join(', ') }}</p>
</div>
{% endif %}

<div class="footer">
  <p>Generated by SkillGuard v0.2.0 | Multi-engine security scanner for AI Agent Skills</p>
</div>

</body>
</html>
"""


def generate_html_report(result: ScanResult) -> str:
    """Generate a self-contained HTML report from scan results.

    Returns:
        HTML string that can be saved to a file or served.
    """
    verdict_str = result.verdict if isinstance(result.verdict, str) else result.verdict.value
    verdict_color = _VERDICT_COLORS.get(verdict_str, "#9ca3af")
    verdict_label = verdict_str.upper().replace("_", " ")

    # Collect and sort all findings
    all_findings: list[Any] = []
    for er in result.engine_results:
        all_findings.extend(er.findings)

    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    critical_count = result.findings_by_severity.get("critical", 0)

    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(_HTML_TEMPLATE)

    return template.render(
        result=result,
        verdict_color=verdict_color,
        verdict_label=verdict_label,
        all_findings=all_findings,
        critical_count=critical_count,
        severity_colors=_SEVERITY_COLORS,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
