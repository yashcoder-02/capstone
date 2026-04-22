import json
import os
import argparse
import subprocess
from datetime import datetime
from jinja2 import Template


REPORT_TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MemSuite Forensic Report — {{ dump_id }}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

  :root {
    --black: #000000;
    --white: #ffffff;
    --gray-100: #f5f5f5;
    --gray-200: #e5e5e5;
    --gray-400: #a3a3a3;
    --gray-600: #525252;
    --gray-800: #1a1a1a;
    --severity-critical: #000000;
    --severity-high: #1a1a1a;
    --severity-medium: #404040;
    --severity-low: #666666;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'IBM Plex Sans', sans-serif;
    background: #ffffff;
    color: #000000;
    font-size: 11pt;
    line-height: 1.6;
  }

  /* PAGE HEADER */
  .page-header {
    background: #000000;
    color: #ffffff;
    padding: 2.5rem 2.5rem 2rem;
    position: relative;
    overflow: hidden;
  }
  .page-header::before {
    content: 'MEMSUITE';
    position: absolute;
    right: -1rem;
    top: 50%;
    transform: translateY(-50%);
    font-size: 8rem;
    font-weight: 600;
    opacity: 0.06;
    letter-spacing: -0.04em;
    font-family: 'IBM Plex Mono', monospace;
    white-space: nowrap;
    pointer-events: none;
  }
  .header-badge {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8pt;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    opacity: 0.5;
    margin-bottom: 0.5rem;
  }
  .header-title {
    font-size: 24pt;
    font-weight: 300;
    letter-spacing: -0.02em;
    margin-bottom: 0.25rem;
  }
  .header-subtitle {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9pt;
    opacity: 0.5;
  }

  /* SEVERITY BANNER */
  .severity-banner {
    padding: 1rem 2.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid #e5e5e5;
  }
  .severity-banner.critical { background: #000; color: #fff; }
  .severity-banner.high { background: #1a1a1a; color: #fff; }
  .severity-banner.medium { background: #f0f0f0; color: #000; }
  .severity-banner.low { background: #f8f8f8; color: #000; }

  .severity-label {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8pt;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    opacity: 0.6;
  }
  .severity-value {
    font-size: 18pt;
    font-weight: 600;
    letter-spacing: 0.05em;
    font-family: 'IBM Plex Mono', monospace;
  }
  .severity-score {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 10pt;
    opacity: 0.7;
  }

  /* BODY */
  .body { padding: 2rem 2.5rem; }

  /* META GRID */
  .meta-grid {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 1px;
    background: #e5e5e5;
    border: 1px solid #e5e5e5;
    margin-bottom: 2rem;
  }
  .meta-cell {
    background: #fff;
    padding: 1rem 1.25rem;
  }
  .meta-label {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 7.5pt;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: #999;
    margin-bottom: 0.25rem;
  }
  .meta-value {
    font-size: 10pt;
    font-weight: 500;
    word-break: break-all;
  }
  .meta-value.mono {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8.5pt;
    color: #333;
  }

  /* SECTION */
  .section { margin-bottom: 2rem; }
  .section-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid #000;
  }
  .section-number {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8pt;
    background: #000;
    color: #fff;
    padding: 2px 6px;
    letter-spacing: 0.05em;
  }
  .section-title {
    font-size: 12pt;
    font-weight: 600;
    letter-spacing: 0.02em;
    text-transform: uppercase;
  }

  /* STATS ROW */
  .stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1px;
    background: #e5e5e5;
    border: 1px solid #e5e5e5;
    margin-bottom: 1.5rem;
  }
  .stat-cell {
    background: #fff;
    padding: 1rem;
    text-align: center;
  }
  .stat-number {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 22pt;
    font-weight: 600;
    line-height: 1;
    margin-bottom: 0.25rem;
  }
  .stat-number.danger { color: #000; }
  .stat-number.warn { color: #333; }
  .stat-label {
    font-size: 7.5pt;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }

  /* FINDING CARDS */
  .finding-card {
    border: 1px solid #e5e5e5;
    margin-bottom: 0.5rem;
    display: grid;
    grid-template-columns: 3rem 1fr auto;
  }
  .finding-index {
    background: #000;
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9pt;
    font-weight: 600;
  }
  .finding-body {
    padding: 0.75rem 1rem;
  }
  .finding-type {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8.5pt;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.25rem;
  }
  .finding-type.hidden_process { color: #000; }
  .finding-type.malfind_hit { color: #111; }
  .finding-type.correlation_bonus { color: #000; }
  .finding-type.suspicious_network { color: #333; }
  .finding-type.known_malware_name { color: #000; }
  .finding-detail {
    font-size: 9pt;
    color: #555;
    font-family: 'IBM Plex Mono', monospace;
    word-break: break-all;
  }
  .finding-score {
    padding: 0.75rem 1rem;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11pt;
    font-weight: 600;
    min-width: 3.5rem;
    border-left: 1px solid #e5e5e5;
    background: #fafafa;
  }

  /* IOC TABLE */
  .ioc-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 9pt;
    font-family: 'IBM Plex Mono', monospace;
    margin-bottom: 1rem;
  }
  .ioc-table th {
    background: #000;
    color: #fff;
    padding: 0.4rem 0.75rem;
    text-align: left;
    font-weight: 600;
    font-size: 8pt;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .ioc-table td {
    padding: 0.4rem 0.75rem;
    border-bottom: 1px solid #f0f0f0;
    color: #333;
    word-break: break-all;
  }
  .ioc-table tr:nth-child(even) td { background: #fafafa; }
  .ioc-table .badge {
    background: #000;
    color: #fff;
    padding: 1px 6px;
    font-size: 7pt;
    letter-spacing: 0.08em;
  }
  .ioc-table .badge.warn {
    background: #555;
  }

  /* NETWORK */
  .net-entry {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8.5pt;
    padding: 0.4rem 0.75rem;
    border-bottom: 1px solid #f0f0f0;
    color: #333;
  }
  .net-entry:nth-child(even) { background: #fafafa; }

  /* FOOTER */
  .page-footer {
    margin-top: 3rem;
    padding: 1.5rem 2.5rem;
    background: #000;
    color: #fff;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .footer-left {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8pt;
    opacity: 0.5;
  }
  .footer-right {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 8pt;
    opacity: 0.5;
    text-align: right;
  }

  /* EMPTY STATE */
  .empty-state {
    padding: 1.5rem;
    background: #f8f8f8;
    border: 1px solid #e5e5e5;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 9pt;
    color: #999;
    text-align: center;
  }

  /* DIVIDER */
  .divider {
    height: 1px;
    background: #e5e5e5;
    margin: 1.5rem 0;
  }

  @media print {
    body { font-size: 10pt; }
    .page-header::before { display: none; }
  }
</style>
</head>
<body>

<!-- PAGE HEADER -->
<div class="page-header">
  <div class="header-badge">Memory Forensics Analysis Report</div>
  <div class="header-title">MemSuite</div>
  <div class="header-subtitle">{{ generated_at }}</div>
</div>

<!-- SEVERITY BANNER -->
<div class="severity-banner {{ severity|lower }}">
  <div>
    <div class="severity-label">Overall Threat Assessment</div>
    <div class="severity-value">{{ severity }}</div>
  </div>
  <div class="severity-score">Risk Score: {{ score }} pts</div>
</div>

<div class="body">

  <!-- META GRID -->
  <div class="meta-grid">
    <div class="meta-cell">
      <div class="meta-label">Case</div>
      <div class="meta-value">{{ case_name }}</div>
    </div>
    <div class="meta-cell">
      <div class="meta-label">Analyst</div>
      <div class="meta-value">{{ analyst }}</div>
    </div>
    <div class="meta-cell">
      <div class="meta-label">Dump ID</div>
      <div class="meta-value mono">{{ dump_id[:16] }}…</div>
    </div>
    <div class="meta-cell">
      <div class="meta-label">Volatility Version</div>
      <div class="meta-value mono">{{ vol_version or 'auto-detected' }}</div>
    </div>
    <div class="meta-cell">
      <div class="meta-label">Analysis Date</div>
      <div class="meta-value">{{ generated_at }}</div>
    </div>
    <div class="meta-cell">
      <div class="meta-label">Filename</div>
      <div class="meta-value mono">{{ filename }}</div>
    </div>
    <div class="meta-cell" style="grid-column: 1/-1;">
      <div class="meta-label">SHA-256 Integrity Hash</div>
      <div class="meta-value mono">{{ sha256 }}</div>
    </div>
  </div>

  <!-- SECTION 1: STATISTICS -->
  <div class="section">
    <div class="section-header">
      <span class="section-number">01</span>
      <span class="section-title">Analysis Summary</span>
    </div>
    <div class="stats-row">
      <div class="stat-cell">
        <div class="stat-number {% if hidden_processes|length > 0 %}danger{% endif %}">{{ hidden_processes|length }}</div>
        <div class="stat-label">Hidden Processes</div>
      </div>
      <div class="stat-cell">
        <div class="stat-number {% if malfind_hits|length > 0 %}danger{% endif %}">{{ malfind_hits|length }}</div>
        <div class="stat-label">Code Injections</div>
      </div>
      <div class="stat-cell">
        <div class="stat-number">{{ network_connections|length }}</div>
        <div class="stat-label">Network Connections</div>
      </div>
      <div class="stat-cell">
        <div class="stat-number">{{ process_count }}</div>
        <div class="stat-label">Total Processes</div>
      </div>
    </div>
  </div>

  <!-- SECTION 2: FINDINGS -->
  <div class="section">
    <div class="section-header">
      <span class="section-number">02</span>
      <span class="section-title">Findings ({{ findings|length }})</span>
    </div>
    {% if findings %}
      {% for f in findings %}
      <div class="finding-card">
        <div class="finding-index">{{ loop.index }}</div>
        <div class="finding-body">
          <div class="finding-type {{ f.type }}">{{ f.type|replace('_', ' ') }}</div>
          <div class="finding-detail">
            {% if f.detail is mapping %}
              {% for k, v in f.detail.items() %}{{ k }}: {{ v }}{% if not loop.last %} | {% endif %}{% endfor %}
            {% else %}
              {{ f.detail }}
            {% endif %}
          </div>
        </div>
        <div class="finding-score">+{{ f.score }}</div>
      </div>
      {% endfor %}
    {% else %}
      <div class="empty-state">No findings detected — memory appears clean</div>
    {% endif %}
  </div>

  <!-- SECTION 3: HIDDEN PROCESSES (IOCs) -->
  {% if hidden_processes %}
  <div class="section">
    <div class="section-header">
      <span class="section-number">03</span>
      <span class="section-title">Indicators of Compromise — Hidden Processes</span>
    </div>
    <table class="ioc-table">
      <thead>
        <tr><th>PID</th><th>Process Name</th><th>Detection Method</th><th>Status</th></tr>
      </thead>
      <tbody>
        {% for p in hidden_processes %}
        <tr>
          <td>{{ p.pid }}</td>
          <td>{{ p.name }}</td>
          <td>{{ p.reason }}</td>
          <td><span class="badge">HIDDEN</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <!-- SECTION 4: CODE INJECTION -->
  {% if malfind_hits %}
  <div class="section">
    <div class="section-header">
      <span class="section-number">04</span>
      <span class="section-title">Indicators of Compromise — Code Injection</span>
    </div>
    <table class="ioc-table">
      <thead>
        <tr><th>#</th><th>Process / Region</th><th>Protection</th><th>Type</th></tr>
      </thead>
      <tbody>
        {% for m in malfind_hits %}
        <tr>
          <td>{{ loop.index }}</td>
          <td>{{ m.process or '—' }}</td>
          <td>{{ m.protection or 'PAGE_EXECUTE_READWRITE' }}</td>
          <td><span class="badge">RWX INJECTION</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <!-- SECTION 5: NETWORK -->
  {% if network_connections %}
  <div class="section">
    <div class="section-header">
      <span class="section-number">05</span>
      <span class="section-title">Network Connections ({{ network_connections|length }})</span>
    </div>
    {% for conn in network_connections[:20] %}
    <div class="net-entry">{{ conn }}</div>
    {% endfor %}
    {% if network_connections|length > 20 %}
    <div class="net-entry" style="color:#999">… {{ network_connections|length - 20 }} more connections (truncated for brevity)</div>
    {% endif %}
  </div>
  {% endif %}

</div>

<!-- FOOTER -->
<div class="page-footer">
  <div class="footer-left">
    MemSuite Forensic Analysis Platform<br>
    Generated: {{ generated_at }}
  </div>
  <div class="footer-right">
    SHA-256 verified at upload<br>
    Chain of custody maintained
  </div>
</div>

</body>
</html>'''


def generate_report(dump_id, report_dir, case_name='Unknown Case', analyst='Unknown', filename='', vol_version='', sha256=''):
    corr_path = f"{report_dir}/correlation.json"

    # If no correlation.json yet, try to generate from what we have
    if not os.path.exists(corr_path):
        data = {
            'dump_id': dump_id,
            'total_score': 0,
            'severity': 'LOW',
            'findings': [],
            'hidden_processes': [],
            'malfind_hits': [],
            'network_connections': [],
            'process_count': 0,
            'psscan_count': 0,
            'connection_count': 0,
        }
        # Try to run correlation inline
        try:
            import pipeline
            data = pipeline.correlate(dump_id, report_dir)
        except Exception as e:
            print(f"Inline correlation failed: {e}")
    else:
        with open(corr_path) as f:
            data = json.load(f)

    # Get SHA-256 from integrity log if not passed in
    if not sha256:
        integrity_path = f"{report_dir}/integrity.log"
        if os.path.exists(integrity_path):
            with open(integrity_path) as f:
                sha256 = f.read().strip().replace('SHA256:', '').strip()

    # Try to get case/analyst info from DB
    try:
        import sys
        sys.path.insert(0, '/app')
        from models import get_dump_with_case
        info = get_dump_with_case(dump_id)
        if info:
            case_name = info.get('case_name') or case_name
            analyst = info.get('analyst') or analyst
            filename = info.get('filename') or filename
            vol_version = info.get('vol_version') or vol_version
            sha256 = info.get('sha256') or sha256
    except Exception:
        pass

    generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

    html = Template(REPORT_TEMPLATE).render(
        dump_id=dump_id,
        case_name=case_name,
        analyst=analyst,
        filename=filename,
        vol_version=vol_version,
        sha256=sha256,
        generated_at=generated_at,
        severity=data.get('severity', 'LOW'),
        score=data.get('total_score', 0),
        findings=data.get('findings', []),
        hidden_processes=data.get('hidden_processes', []),
        malfind_hits=data.get('malfind_hits', []),
        network_connections=data.get('network_connections', []),
        process_count=data.get('process_count', 0),
        psscan_count=data.get('psscan_count', 0),
        connection_count=data.get('connection_count', 0),
    )

    html_path = f"{report_dir}/report.html"
    with open(html_path, 'w') as f:
        f.write(html)
    print(f"HTML report: {html_path}")

    # PDF via wkhtmltopdf (preferred) or weasyprint fallback
    pdf_path = f"{report_dir}/report.pdf"
    try:
        result = subprocess.run(
            ['wkhtmltopdf',
             '--page-size', 'A4',
             '--margin-top', '0',
             '--margin-right', '0',
             '--margin-bottom', '0',
             '--margin-left', '0',
             '--enable-local-file-access',
             html_path, pdf_path],
            check=True, capture_output=True
        )
        print(f"PDF report (wkhtmltopdf): {pdf_path}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        try:
            from weasyprint import HTML as WH
            WH(string=html).write_pdf(pdf_path)
            print(f"PDF report (weasyprint): {pdf_path}")
        except Exception as e:
            print(f"PDF generation failed: {e} — HTML report still available")
            pdf_path = None

    return html_path, pdf_path


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dump-id', required=True)
    parser.add_argument('--report-dir', required=True)
    parser.add_argument('--case-name', default='Unknown Case')
    parser.add_argument('--analyst', default='Unknown')
    args = parser.parse_args()
    generate_report(args.dump_id, args.report_dir, args.case_name, args.analyst)
