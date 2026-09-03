"""Pydantic data models for report export API requests."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.analysis import AnalysisResultResponse


class ReportExportRequest(BaseModel):
    """Request schema for exporting analysis results as downloadable reports."""

    model_config = ConfigDict(extra="forbid")

    format: Literal["json", "html", "pdf"] = Field(
        ...,
        description="Target report format ('json', 'html', or 'pdf')",
    )
    analysis_result: AnalysisResultResponse = Field(
        ...,
        description="Validated analysis result structure conforming to shared contracts",
    )
