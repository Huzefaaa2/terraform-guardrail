from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


class Finding(BaseModel):
    rule_id: str
    severity: Literal["low", "medium", "high"]
    message: str
    path: str | None = None
    detail: dict[str, Any] | None = None


class ScanSummary(BaseModel):
    scanned_files: int = 0
    findings: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanReport(BaseModel):
    scanned_path: str
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    summary: ScanSummary
    findings: list[Finding]
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def empty(cls, scanned_path: Path) -> ScanReport:
        return cls(scanned_path=str(scanned_path), summary=ScanSummary(), findings=[])
