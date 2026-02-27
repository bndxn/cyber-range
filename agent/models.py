"""Pydantic models for structured agent outputs."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Vulnerability(BaseModel):
    """A single discovered vulnerability."""

    title: str = Field(description="Short descriptive title")
    cve_id: Optional[str] = Field(
        default=None, description="CVE identifier if applicable"
    )
    severity: Severity
    cvss: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    endpoint: str = Field(description="Affected URL / endpoint")
    description: str = Field(description="What the vulnerability is")
    evidence: str = Field(description="Proof that the vulnerability exists")
    exploitation_steps: list[str] = Field(
        description="Step-by-step exploitation procedure"
    )
    remediation: str = Field(description="How to fix the vulnerability")


class VulnerabilityReport(BaseModel):
    """Full structured report produced by the security agent."""

    target: str = Field(description="Base URL of the assessed target")
    summary: str = Field(description="Executive summary of findings")
    vulnerabilities: list[Vulnerability]
    total_findings: int
    critical_count: int
    high_count: int
    flags_captured: list[str] = Field(
        default_factory=list,
        description="Any CTF flags discovered during exploitation",
    )


class ExploitResult(BaseModel):
    """Result of a single exploit attempt."""

    success: bool
    payload: str
    response_snippet: str = Field(description="Relevant portion of the response")
    notes: str = Field(default="", description="Additional observations")
