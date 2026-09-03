# Reports

This package provides forensic report generators for SecureMailScope analysis results.

## Module Status

- `json_report.py`: **Implemented**. Serializes contract-compliant analysis results into deterministic, formatted JSON (`generate_json_report`, `export_json_report`).
- `html_report.py`: **Implemented**. Generates standalone, offline-ready HTML forensic reports with embedded CSS (`generate_html_report`, `export_html_report`).
- `pdf_report.py`: **Implemented**. Generates standalone, printable PDF forensic reports using ReportLab (`generate_pdf_report`, `export_pdf_report`).

## JSON Report Generator (`json_report.py`)

- **Interface:**
  - `generate_json_report(analysis_result: AnalysisResultResponse | dict, indent: int = 2) -> str`
  - `export_json_report(analysis_result: AnalysisResultResponse | dict, output_path: str | Path, indent: int = 2) -> Path`
- **Output Format:** Clean, deterministic JSON strictly adhering to `shared/contracts/analysis_result_schema.json`.
- **Validation:** Pydantic contract validation (`extra="forbid"`).

## HTML Report Generator (`html_report.py`)

- **Interface:**
  - `generate_html_report(analysis_result: AnalysisResultResponse | dict) -> str`
  - `export_html_report(analysis_result: AnalysisResultResponse | dict, output_path: str | Path) -> Path`
- **Output Format:** Standalone, semantic HTML5 document with embedded CSS styling and `@media print` print-readiness.
- **Offline Behavior:** 100% self-contained with zero external CDN dependencies, remote fonts, or external scripts. Directly openable in any browser offline.
- **Security:** Strict Jinja2 auto-escaping (`autoescape=True`) prevents HTML/script injection from dynamic PCAP/packet attributes.
- **Validation:** Enforces strict compliance with `shared/contracts/analysis_result_schema.json` via Pydantic; invalid data is rejected with `ValidationError`.

## PDF Report Generator (`pdf_report.py`)

- **Interface:**
  - `generate_pdf_report(analysis_result: AnalysisResultResponse | dict, output_path: str | Path | None = None) -> Path | bytes`
  - `export_pdf_report(analysis_result: AnalysisResultResponse | dict, output_path: str | Path) -> Path`
- **Output Format:** Standalone, printable, multi-page PDF document.
- **Offline Behavior:** 100% offline, CPU-friendly, requires zero external services or headless browser automation.
- **Layout & Typography:**
  - Two-pass `_NumberedCanvas` providing running headers and "Page X of Y" footers.
  - Automatic table cell wrapping with `Paragraph` flowables.
  - Severity-colored finding headers and green-accented remediation boxes.
  - Automatic parent directory creation on disk export.
- **Dependencies:** `reportlab==5.0.1` (lightweight, deterministic PDF generation).
- **Validation:** Enforces strict compliance with `shared/contracts/analysis_result_schema.json` via Pydantic.

## Current Limitations

- Report download / export API endpoints in the FastAPI backend are pending a future task.
- Generated report output files should not be committed to source control.
