"""JSON report generator for SecureMailScope.

Serializes validated analysis results into deterministic, contract-compliant
JSON reports suitable for disk export, API download, and consumption by
downstream report renderers or frontends.

Conforms strictly to:
- shared/contracts/analysis_result_schema.json
- shared/contracts/session_schema.json
- shared/contracts/finding_schema.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from backend.app.models.analysis import AnalysisResultResponse


def generate_json_report(
    analysis_result: AnalysisResultResponse | dict[str, Any],
    indent: int = 2,
) -> str:
    """Generate a clean, deterministic, contract-compliant JSON report string.

    Validates that the input conforms strictly to
    `shared/contracts/analysis_result_schema.json`.

    Args:
        analysis_result: An AnalysisResultResponse model instance or a raw dictionary
            representing analysis results.
        indent: Indentation level for pretty-printed JSON output (default: 2).

    Returns:
        A formatted JSON string representing the analysis report.

    Raises:
        ValidationError: If the analysis result data violates the shared contract schema.
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

    return validated_model.model_dump_json(indent=indent)


def export_json_report(
    analysis_result: AnalysisResultResponse | dict[str, Any],
    output_path: str | Path,
    indent: int = 2,
) -> Path:
    """Serialize and write a contract-compliant JSON report directly to a file.

    Args:
        analysis_result: Validated model or dict conforming to analysis_result_schema.json.
        output_path: Destination file path.
        indent: Indentation level for formatting (default: 2).

    Returns:
        Path to the written report file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    report_json = generate_json_report(analysis_result, indent=indent)
    path.write_text(report_json, encoding="utf-8")
    return path
