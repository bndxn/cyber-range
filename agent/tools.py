"""
Agent tools — the capabilities the LangChain agent can invoke.

Demonstrates:
  • Custom tool creation with the @tool decorator
  • Tool orchestration (the agent decides which tool to call and when)
  • Structured tool inputs via Pydantic arg schemas
  • Integration with RAG (lookup_cve) and structured outputs (generate_report)
"""

from __future__ import annotations

import json
from typing import Optional

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from agent.models import Severity, Vulnerability, VulnerabilityReport
from agent.rag import CVEKnowledgeBase

_kb: CVEKnowledgeBase | None = None


def _get_kb() -> CVEKnowledgeBase:
    global _kb
    if _kb is None:
        _kb = CVEKnowledgeBase()
    return _kb


# ── Tool input schemas ──────────────────────────────────────────────


class HttpGetInput(BaseModel):
    url: str = Field(description="Full URL to request (including query params)")


class HttpGetCustomHeaderInput(BaseModel):
    url: str = Field(description="Full URL to request")
    header_name: str = Field(description="HTTP header name to set")
    header_value: str = Field(description="HTTP header value (may contain payloads)")


class CVELookupInput(BaseModel):
    query: str = Field(
        description="Natural-language query about a vulnerability or CVE"
    )


class ReportFinding(BaseModel):
    title: str
    cve_id: Optional[str] = None
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, or INFO")
    cvss: Optional[float] = None
    endpoint: str
    description: str
    evidence: str
    exploitation_steps: list[str]
    remediation: str


class GenerateReportInput(BaseModel):
    target: str = Field(description="Base URL of the target")
    summary: str = Field(description="Executive summary")
    findings: list[ReportFinding]
    flags_captured: list[str] = Field(default_factory=list)


# ── Tool implementations ────────────────────────────────────────────


@tool("http_get", args_schema=HttpGetInput)
def http_get(url: str) -> str:
    """Make an HTTP GET request and return status code, headers, and body.
    Use this for reconnaissance, testing endpoints, and sending payloads via query parameters."""
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers_str = "\n".join(f"  {k}: {v}" for k, v in resp.headers.items())
        body = resp.text[:3000]
        return (
            f"Status: {resp.status_code}\n"
            f"Headers:\n{headers_str}\n"
            f"Body:\n{body}"
        )
    except requests.RequestException as exc:
        return f"Request failed: {exc}"


@tool("http_get_custom_header", args_schema=HttpGetCustomHeaderInput)
def http_get_custom_header(url: str, header_name: str, header_value: str) -> str:
    """Make an HTTP GET request with a custom/modified header.
    Essential for Shellshock testing — inject payloads into User-Agent or other headers."""
    try:
        resp = requests.get(
            url,
            headers={header_name: header_value},
            timeout=10,
            allow_redirects=True,
        )
        headers_str = "\n".join(f"  {k}: {v}" for k, v in resp.headers.items())
        body = resp.text[:3000]
        return (
            f"Status: {resp.status_code}\n"
            f"Headers:\n{headers_str}\n"
            f"Body:\n{body}"
        )
    except requests.RequestException as exc:
        return f"Request failed: {exc}"


@tool("lookup_cve", args_schema=CVELookupInput)
def lookup_cve(query: str) -> str:
    """Search the CVE knowledge base using semantic similarity (RAG).
    Use this to research vulnerabilities based on discovered technologies, version numbers, or attack patterns."""
    kb = _get_kb()
    return kb.search(query, k=3)


@tool("generate_report", args_schema=GenerateReportInput)
def generate_report(
    target: str,
    summary: str,
    findings: list[ReportFinding],
    flags_captured: list[str] | None = None,
) -> str:
    """Generate a structured vulnerability assessment report from findings.
    Call this after all testing and exploitation is complete."""
    vulns = []
    crit = high = 0
    for f in findings:
        sev = Severity(f.severity.upper())
        if sev == Severity.CRITICAL:
            crit += 1
        elif sev == Severity.HIGH:
            high += 1
        vulns.append(
            Vulnerability(
                title=f.title,
                cve_id=f.cve_id,
                severity=sev,
                cvss=f.cvss,
                endpoint=f.endpoint,
                description=f.description,
                evidence=f.evidence,
                exploitation_steps=f.exploitation_steps,
                remediation=f.remediation,
            )
        )

    report = VulnerabilityReport(
        target=target,
        summary=summary,
        vulnerabilities=vulns,
        total_findings=len(vulns),
        critical_count=crit,
        high_count=high,
        flags_captured=flags_captured or [],
    )

    return json.dumps(report.model_dump(), indent=2)


ALL_TOOLS = [http_get, http_get_custom_header, lookup_cve, generate_report]
