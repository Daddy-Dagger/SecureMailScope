"""HTML report generator for SecureMailScope.

Renders validated analysis results into a standalone, self-contained,
offline-ready HTML forensic report with embedded CSS styling.

Conforms strictly to:
- shared/contracts/analysis_result_schema.json
- shared/contracts/session_schema.json
- shared/contracts/finding_schema.json
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment

from backend.app.models.analysis import AnalysisResultResponse

# Standalone Jinja2 template with embedded styling and zero external CDN/font dependencies
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureMailScope — Email Cryptographic Security Analysis</title>
  <style>
    :root {
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --text: #0f172a;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --primary: #1e293b;
      --badge-critical: #ef4444;
      --badge-high: #f97316;
      --badge-medium: #f59e0b;
      --badge-low: #3b82f6;
      --badge-info: #64748b;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 2rem 1rem;
    }

    .container {
      max-width: 1000px;
      margin: 0 auto;
    }

    header {
      background: var(--primary);
      color: #ffffff;
      padding: 2rem;
      border-radius: 8px 8px 0 0;
    }

    header h1 {
      font-size: 1.75rem;
      font-weight: 700;
      margin-bottom: 0.25rem;
    }

    header .subtitle {
      color: #94a3b8;
      font-size: 0.95rem;
    }

    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-top: none;
      padding: 1.5rem 2rem;
      margin-bottom: 1.5rem;
    }

    .card:last-of-type {
      border-radius: 0 0 8px 8px;
    }

    h2 {
      font-size: 1.25rem;
      font-weight: 600;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 2px solid var(--border);
      color: var(--text);
    }

    .grid-2 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1.5rem;
      margin-bottom: 1rem;
    }

    .meta-box {
      background: #f1f5f9;
      border-radius: 6px;
      padding: 1rem 1.25rem;
    }

    .meta-row {
      display: flex;
      justify-content: space-between;
      padding: 0.35rem 0;
      font-size: 0.9rem;
    }

    .meta-label {
      color: var(--text-muted);
      font-weight: 500;
    }

    .meta-val {
      font-weight: 600;
      word-break: break-all;
    }

    .summary-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
      margin-top: 1rem;
    }

    .metric-card {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
      text-align: center;
    }

    .metric-val {
      font-size: 1.5rem;
      font-weight: 700;
      color: var(--primary);
    }

    .metric-label {
      font-size: 0.8rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
      margin-top: 0.75rem;
    }

    th, td {
      padding: 0.75rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    th {
      background: #f1f5f9;
      color: var(--text-muted);
      font-weight: 600;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    tr:hover td {
      background: #f8fafc;
    }

    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.825rem;
      background: #f1f5f9;
      padding: 0.15rem 0.35rem;
      border-radius: 4px;
    }

    .badge {
      display: inline-block;
      padding: 0.2rem 0.55rem;
      font-size: 0.75rem;
      font-weight: 700;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #ffffff;
    }

    .badge-critical { background-color: var(--badge-critical); }
    .badge-high { background-color: var(--badge-high); }
    .badge-medium { background-color: var(--badge-medium); }
    .badge-low { background-color: var(--badge-low); }
    .badge-info { background-color: var(--badge-info); }
    .badge-neutral { background-color: #64748b; }

    .finding-item {
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1.25rem;
      margin-bottom: 1rem;
      background: #ffffff;
    }

    .finding-item:last-child {
      margin-bottom: 0;
    }

    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.75rem;
    }

    .finding-title {
      font-size: 1.05rem;
      font-weight: 600;
    }

    .finding-id {
      color: var(--text-muted);
      font-size: 0.85rem;
      margin-left: 0.5rem;
    }

    .finding-body {
      font-size: 0.9rem;
      color: #334155;
      margin-bottom: 0.75rem;
    }

    .recommendation-box {
      background: #f0fdf4;
      border-left: 4px solid #22c55e;
      padding: 0.75rem 1rem;
      font-size: 0.875rem;
      color: #166534;
      border-radius: 0 4px 4px 0;
    }

    .recommendation-box strong {
      display: block;
      margin-bottom: 0.25rem;
      color: #15803d;
    }

    .empty-state {
      padding: 2rem;
      text-align: center;
      color: var(--text-muted);
      font-style: italic;
      background: #f8fafc;
      border-radius: 6px;
      border: 1px dashed var(--border);
    }

    footer {
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-top: 2rem;
    }

    @media print {
      body {
        padding: 0;
        background: #ffffff;
      }
      .card {
        border: none;
        padding: 1rem 0;
      }
      header {
        border-radius: 0;
      }
      .finding-item {
        break-inside: avoid;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>SecureMailScope — Email Cryptographic Security Analysis</h1>
      <p class="subtitle">Passive Network Forensics Forensic Report &bull; SIH26159</p>
    </header>

    <main>
      <!-- SECTION: Capture Information & Overall Assessment -->
      <section class="card" aria-labelledby="sec-overview">
        <h2 id="sec-overview">Capture Overview &amp; Assessment</h2>
        <div class="grid-2">
          <div class="meta-box">
            <div class="meta-row">
              <span class="meta-label">Analyzed File:</span>
              <span class="meta-val"><code>{{ model.file }}</code></span>
            </div>
            <div class="meta-row">
              <span class="meta-label">Total Packet Count:</span>
              <span class="meta-val">{{ model.packet_count }}</span>
            </div>
          </div>

          <div class="meta-box">
            <div class="meta-row">
              <span class="meta-label">Overall Score:</span>
              <span class="meta-val">
                {% if model.overall_score is not none %}
                  {{ model.overall_score }}
                {% else %}
                  <span class="badge badge-neutral">Not available</span>
                {% endif %}
              </span>
            </div>
            <div class="meta-row">
              <span class="meta-label">Risk Level:</span>
              <span class="meta-val">
                {% if model.risk_level is not none %}
                  <span class="badge badge-high">{{ model.risk_level }}</span>
                {% else %}
                  <span class="badge badge-neutral">Not available</span>
                {% endif %}
              </span>
            </div>
          </div>
        </div>

        <div class="summary-cards">
          <div class="metric-card">
            <div class="metric-val">{{ model.summary.smtp_sessions }}</div>
            <div class="metric-label">SMTP Sessions</div>
          </div>
          <div class="metric-card">
            <div class="metric-val">{{ model.summary.imap_sessions }}</div>
            <div class="metric-label">IMAP Sessions</div>
          </div>
          <div class="metric-card">
            <div class="metric-val">{{ model.summary.pop3_sessions }}</div>
            <div class="metric-label">POP3 Sessions</div>
          </div>
        </div>
      </section>

      <!-- SECTION: Email Sessions -->
      <section class="card" aria-labelledby="sec-sessions">
        <h2 id="sec-sessions">Extracted Email Sessions</h2>
        {% if model.sessions %}
          <div style="overflow-x: auto;">
            <table>
              <thead>
                <tr>
                  <th>Session ID</th>
                  <th>Protocol</th>
                  <th>Client Endpoint</th>
                  <th>Server Endpoint</th>
                  <th>Packets</th>
                  <th>Start Time (UTC)</th>
                  <th>End Time (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {% for session in model.sessions %}
                  <tr>
                    <td><code>{{ session.session_id }}</code></td>
                    <td><span class="badge badge-info">{{ session.protocol }}</span></td>
                    <td><code>{{ session.client_ip }}:{{ session.client_port }}</code></td>
                    <td><code>{{ session.server_ip }}:{{ session.server_port }}</code></td>
                    <td>{{ session.packet_count }}</td>
                    <td><small>{{ session.start_time }}</small></td>
                    <td><small>{{ session.end_time }}</small></td>
                  </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        {% else %}
          <div class="empty-state">No sessions detected.</div>
        {% endif %}
      </section>

      <!-- SECTION: Security Findings -->
      <section class="card" aria-labelledby="sec-findings">
        <h2 id="sec-findings">Cryptographic Security Findings</h2>
        {% if model.findings %}
          {% for finding in model.findings %}
            <article class="finding-item">
              <div class="finding-header">
                <div>
                  <span class="finding-title">{{ finding.title }}</span>
                  <span class="finding-id">({{ finding.finding_id }})</span>
                </div>
                <div>
                  {% if finding.severity == 'CRITICAL' %}
                    <span class="badge badge-critical">CRITICAL</span>
                  {% elif finding.severity == 'HIGH' %}
                    <span class="badge badge-high">HIGH</span>
                  {% elif finding.severity == 'MEDIUM' %}
                    <span class="badge badge-medium">MEDIUM</span>
                  {% elif finding.severity == 'LOW' %}
                    <span class="badge badge-low">LOW</span>
                  {% else %}
                    <span class="badge badge-info">{{ finding.severity }}</span>
                  {% endif %}
                </div>
              </div>
              <p class="finding-body">{{ finding.explanation }}</p>
              <div class="recommendation-box">
                <strong>Remediation Recommendation</strong>
                {{ finding.recommendation }}
              </div>
            </article>
          {% endfor %}
        {% else %}
          <div class="empty-state">No security findings available.</div>
        {% endif %}
      </section>
    </main>

    <footer>
      <p>SecureMailScope Forensic Report &bull; ₹0 Cost Local Analysis &bull; Privacy Preserving</p>
    </footer>
  </div>
</body>
</html>
"""

# Initialize Jinja2 environment with strict HTML auto-escaping
_JINJA_ENV = Environment(autoescape=True)
_TEMPLATE = _JINJA_ENV.from_string(_HTML_TEMPLATE)


def generate_html_report(
    analysis_result: AnalysisResultResponse | dict[str, Any],
) -> str:
    """Generate a clean, self-contained, offline-ready HTML forensic report.

    Validates that input strictly conforms to
    `shared/contracts/analysis_result_schema.json`.

    Args:
        analysis_result: An AnalysisResultResponse model instance or a raw dictionary
            representing analysis results.

    Returns:
        A standalone HTML5 string with embedded CSS and auto-escaped content.

    Raises:
        ValidationError: If the input data violates the shared schema contract.
        TypeError: If input is neither an AnalysisResultResponse nor a dictionary.
    """
    if isinstance(analysis_result, AnalysisResultResponse):
        validated_model = analysis_result
    elif isinstance(analysis_result, dict):
        validated_model = AnalysisResultResponse.model_validate(analysis_result)
    else:
        raise TypeError(
            f"Expected AnalysisResultResponse or dict, got {type(analysis_result).__name__}"
        )

    return _TEMPLATE.render(model=validated_model)


def export_html_report(
    analysis_result: AnalysisResultResponse | dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Serialize and write a standalone HTML forensic report to a file.

    Args:
        analysis_result: Validated model or dict conforming to analysis_result_schema.json.
        output_path: Destination file path.

    Returns:
        Path to the written HTML file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    html_content = generate_html_report(analysis_result)
    path.write_text(html_content, encoding="utf-8")
    return path
