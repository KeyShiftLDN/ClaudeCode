#!/usr/bin/env python3
"""
Prowler MCP Server

A Model Context Protocol server that provides cloud security assessment
capabilities using Prowler for AWS, Azure, and GCP.

Tools:
    - prowler_scan: Run security assessment on cloud provider
    - prowler_compliance: Check compliance against frameworks
    - list_checks: List available security checks
    - list_compliance_frameworks: List available compliance frameworks
    - get_scan_results: Retrieve previous scan results
    - list_active_scans: Show running scans
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    TextContent,
    Tool,
)
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("prowler-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    output_dir: str = Field(default="/app/output", alias="PROWLER_OUTPUT_DIR")
    default_timeout: int = Field(default=1800, alias="PROWLER_TIMEOUT")  # 30 min default
    max_concurrent_scans: int = Field(default=1, alias="PROWLER_MAX_CONCURRENT")

    class Config:
        env_prefix = "PROWLER_"


settings = Settings()


class Finding(BaseModel):
    """Model for a security finding."""

    check_id: str
    check_title: str
    severity: str
    status: str  # PASS, FAIL, MANUAL
    status_extended: str | None = None
    resource_id: str | None = None
    resource_arn: str | None = None
    region: str | None = None
    service: str | None = None
    risk: str | None = None
    remediation: str | None = None


class ScanResult(BaseModel):
    """Model for scan results."""

    scan_id: str
    provider: str
    scan_type: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    findings: list[Finding] = []
    stats: dict[str, Any] = {}
    error: str | None = None
    raw_output: str | None = None


# In-memory storage for scan results
scan_results: dict[str, ScanResult] = {}
active_scans: set[str] = set()

CLOUD_PROVIDERS = ["aws", "azure", "gcp", "kubernetes"]

COMPLIANCE_FRAMEWORKS = {
    "aws": [
        "cis_1.4_aws", "cis_1.5_aws", "cis_2.0_aws",
        "aws_foundational_security_best_practices",
        "pci_3.2.1_aws", "hipaa_aws", "soc2_aws",
        "gdpr_aws", "nist_800_53_aws", "nist_800_171_aws",
    ],
    "azure": [
        "cis_1.0_azure", "cis_2.0_azure",
        "azure_security_benchmark",
    ],
    "gcp": [
        "cis_1.0_gcp", "cis_2.0_gcp",
    ],
    "kubernetes": [
        "cis_1.6_kubernetes", "cis_1.7_kubernetes",
    ],
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"]


def parse_prowler_json(output: str) -> list[Finding]:
    """Parse Prowler JSON output."""
    findings = []

    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)

            finding = Finding(
                check_id=data.get("CheckID", data.get("check_id", "unknown")),
                check_title=data.get("CheckTitle", data.get("check_title", "")),
                severity=data.get("Severity", data.get("severity", "informational")),
                status=data.get("Status", data.get("status", "MANUAL")),
                status_extended=data.get("StatusExtended", data.get("status_extended")),
                resource_id=data.get("ResourceId", data.get("resource_id")),
                resource_arn=data.get("ResourceArn", data.get("resource_arn")),
                region=data.get("Region", data.get("region")),
                service=data.get("ServiceName", data.get("service_name")),
                risk=data.get("Risk", data.get("risk")),
                remediation=data.get("Remediation", {}).get("Recommendation", {}).get("Text")
                if isinstance(data.get("Remediation"), dict) else data.get("remediation"),
            )
            findings.append(finding)

        except json.JSONDecodeError:
            continue
        except Exception as e:
            logger.warning(f"Error parsing finding: {e}")
            continue

    return findings


async def run_prowler_scan(
    provider: str,
    checks: list[str] | None = None,
    services: list[str] | None = None,
    regions: list[str] | None = None,
    compliance: str | None = None,
    severity: list[str] | None = None,
    timeout: int | None = None,
) -> ScanResult:
    """Execute a Prowler scan asynchronously."""
    scan_id = str(uuid.uuid4())[:8]
    output_file = Path(settings.output_dir) / f"prowler_{scan_id}"

    result = ScanResult(
        scan_id=scan_id,
        provider=provider,
        scan_type="compliance" if compliance else "security",
        started_at=datetime.now(),
    )
    scan_results[scan_id] = result
    active_scans.add(scan_id)

    # Build prowler command
    cmd = [
        "prowler",
        provider,
        "-M", "json",
        "-o", str(output_file),
        "-F", scan_id,
    ]

    # Add compliance framework
    if compliance:
        cmd.extend(["--compliance", compliance])

    # Add specific checks
    if checks:
        cmd.extend(["-c", ",".join(checks)])

    # Add services filter
    if services:
        cmd.extend(["-s", ",".join(services)])

    # Add regions filter (AWS/Azure)
    if regions:
        cmd.extend(["-f", ",".join(regions)])

    # Add severity filter
    if severity:
        cmd.extend(["--severity", ",".join(severity)])

    logger.info(f"Starting {provider} scan {scan_id}")
    logger.debug(f"Command: {' '.join(cmd)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=float(timeout or settings.default_timeout),
        )

        result.completed_at = datetime.now()

        # Find output file
        output_json = Path(settings.output_dir) / f"prowler-output-{provider}-{scan_id}.json"
        if not output_json.exists():
            # Try alternative naming
            for f in Path(settings.output_dir).glob(f"*{scan_id}*.json"):
                output_json = f
                break

        if output_json.exists():
            output_content = output_json.read_text()
            result.raw_output = output_content
            result.findings = parse_prowler_json(output_content)
        else:
            # Parse stdout as fallback
            stdout_text = stdout.decode()
            result.raw_output = stdout_text

        # Generate stats
        status_counts = {"PASS": 0, "FAIL": 0, "MANUAL": 0}
        severity_counts = {}
        service_counts = {}

        for finding in result.findings:
            status_counts[finding.status] = status_counts.get(finding.status, 0) + 1
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            if finding.service:
                service_counts[finding.service] = service_counts.get(finding.service, 0) + 1

        result.stats = {
            "total_findings": len(result.findings),
            "by_status": status_counts,
            "by_severity": severity_counts,
            "by_service": dict(sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "pass_rate": f"{(status_counts['PASS'] / len(result.findings) * 100):.1f}%" if result.findings else "N/A",
        }

        if process.returncode == 0:
            result.status = "completed"
            logger.info(f"Scan {scan_id} completed: {len(result.findings)} findings")
        else:
            stderr_text = stderr.decode()
            if "error" in stderr_text.lower() and "credential" in stderr_text.lower():
                result.status = "failed"
                result.error = "Authentication failed. Ensure cloud credentials are configured."
            elif result.findings:
                result.status = "completed"
            else:
                result.status = "failed"
                result.error = stderr_text
            logger.error(f"Scan {scan_id} issue: {stderr_text[:200]}")

    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Scan timed out after {timeout or settings.default_timeout} seconds"
        result.completed_at = datetime.now()
        logger.error(f"Scan {scan_id} timed out")

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()
        logger.exception(f"Scan {scan_id} error: {e}")

    finally:
        active_scans.discard(scan_id)
        scan_results[scan_id] = result

    return result


def format_scan_summary(result: ScanResult) -> dict[str, Any]:
    """Format scan result for response."""
    # Get critical/high findings
    critical_findings = [f for f in result.findings if f.severity.lower() in ["critical", "high"] and f.status == "FAIL"]

    findings_summary = []
    for finding in critical_findings[:30]:  # Limit critical findings
        findings_summary.append({
            "check_id": finding.check_id,
            "check_title": finding.check_title,
            "severity": finding.severity,
            "status": finding.status,
            "resource_id": finding.resource_id,
            "region": finding.region,
            "service": finding.service,
        })

    return {
        "scan_id": result.scan_id,
        "provider": result.provider,
        "scan_type": result.scan_type,
        "status": result.status,
        "stats": result.stats,
        "critical_high_findings": findings_summary,
        "error": result.error,
    }


# Create MCP server
app = Server("prowler-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="prowler_scan",
            description="Run security assessment on AWS, Azure, GCP, or Kubernetes. "
            "Checks for misconfigurations, compliance issues, and security best practices.",
            inputSchema={
                "type": "object",
                "properties": {
                    "provider": {
                        "type": "string",
                        "enum": CLOUD_PROVIDERS,
                        "description": "Cloud provider to scan (aws, azure, gcp, kubernetes)",
                    },
                    "services": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific services to scan (e.g., s3, ec2, iam for AWS)",
                    },
                    "regions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Regions to scan (e.g., us-east-1, eu-west-1)",
                    },
                    "severity": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": SEVERITY_LEVELS,
                        },
                        "description": "Filter by severity levels",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds (default 1800 = 30 min)",
                        "default": 1800,
                    },
                },
                "required": ["provider"],
            },
        ),
        Tool(
            name="prowler_compliance",
            description="Check cloud environment against compliance frameworks "
            "(CIS, PCI-DSS, HIPAA, SOC2, GDPR, NIST, etc.).",
            inputSchema={
                "type": "object",
                "properties": {
                    "provider": {
                        "type": "string",
                        "enum": CLOUD_PROVIDERS,
                        "description": "Cloud provider to scan",
                    },
                    "framework": {
                        "type": "string",
                        "description": "Compliance framework (e.g., cis_2.0_aws, pci_3.2.1_aws, hipaa_aws)",
                    },
                    "regions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Regions to scan",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 1800,
                    },
                },
                "required": ["provider", "framework"],
            },
        ),
        Tool(
            name="list_checks",
            description="List available security checks for a cloud provider.",
            inputSchema={
                "type": "object",
                "properties": {
                    "provider": {
                        "type": "string",
                        "enum": CLOUD_PROVIDERS,
                        "description": "Cloud provider",
                    },
                    "service": {
                        "type": "string",
                        "description": "Filter by service (e.g., s3, iam, ec2)",
                    },
                },
                "required": ["provider"],
            },
        ),
        Tool(
            name="list_compliance_frameworks",
            description="List available compliance frameworks for each cloud provider.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="get_scan_results",
            description="Retrieve results from a previous scan by scan ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Scan ID returned from a previous scan",
                    },
                    "show_all_findings": {
                        "type": "boolean",
                        "description": "Include all findings (not just critical/high)",
                        "default": False,
                    },
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="list_active_scans",
            description="List currently running scans.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    try:
        if name == "prowler_scan":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_prowler_scan(
                provider=arguments["provider"],
                services=arguments.get("services"),
                regions=arguments.get("regions"),
                severity=arguments.get("severity"),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "prowler_compliance":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_prowler_scan(
                provider=arguments["provider"],
                compliance=arguments["framework"],
                regions=arguments.get("regions"),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "list_checks":
            provider = arguments["provider"]
            service = arguments.get("service")

            # Run prowler to list checks
            cmd = ["prowler", provider, "--list-checks"]
            if service:
                cmd.extend(["-s", service])

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, _ = await asyncio.wait_for(
                    process.communicate(),
                    timeout=60.0,
                )

                checks = stdout.decode().strip().split("\n")
                checks = [c.strip() for c in checks if c.strip() and not c.startswith("=")]

                return [
                    TextContent(
                        type="text",
                        text=json.dumps({
                            "provider": provider,
                            "service_filter": service,
                            "checks": checks[:100],
                            "total": len(checks),
                        }, indent=2),
                    )
                ]

            except Exception as e:
                return [
                    TextContent(type="text", text=f"Error listing checks: {e}")
                ]

        elif name == "list_compliance_frameworks":
            return [
                TextContent(
                    type="text",
                    text=json.dumps({
                        "compliance_frameworks": COMPLIANCE_FRAMEWORKS,
                        "description": "Available compliance frameworks per cloud provider",
                    }, indent=2),
                )
            ]

        elif name == "get_scan_results":
            scan_id = arguments["scan_id"]
            result = scan_results.get(scan_id)

            if result:
                output = format_scan_summary(result)

                if arguments.get("show_all_findings"):
                    all_findings = []
                    for finding in result.findings[:200]:
                        all_findings.append({
                            "check_id": finding.check_id,
                            "check_title": finding.check_title,
                            "severity": finding.severity,
                            "status": finding.status,
                            "resource_id": finding.resource_id,
                            "region": finding.region,
                        })
                    output["all_findings"] = all_findings

                return [
                    TextContent(
                        type="text",
                        text=json.dumps(output, indent=2),
                    )
                ]
            else:
                return [
                    TextContent(type="text", text=f"Scan '{scan_id}' not found")
                ]

        elif name == "list_active_scans":
            active = [
                {
                    "scan_id": scan_id,
                    "provider": scan_results[scan_id].provider,
                    "scan_type": scan_results[scan_id].scan_type,
                    "started_at": scan_results[scan_id].started_at.isoformat(),
                }
                for scan_id in active_scans
                if scan_id in scan_results
            ]

            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "active_scans": active,
                            "count": len(active),
                            "max_concurrent": settings.max_concurrent_scans,
                        },
                        indent=2,
                    ),
                )
            ]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        logger.exception(f"Error executing tool {name}: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]


@app.list_resources()
async def list_resources() -> list[Resource]:
    """List available resources."""
    resources = []

    for scan_id, result in scan_results.items():
        if result.status == "completed":
            finding_count = len(result.findings)
            resources.append(
                Resource(
                    uri=f"prowler://results/{scan_id}",
                    name=f"Scan Results: {result.provider} ({finding_count} findings)",
                    description=f"{result.scan_type} scan completed at {result.completed_at}",
                    mimeType="application/json",
                )
            )

    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource."""
    if uri.startswith("prowler://results/"):
        scan_id = uri.replace("prowler://results/", "")
        result = scan_results.get(scan_id)
        if result:
            return json.dumps(format_scan_summary(result), indent=2)

    return json.dumps({"error": "Resource not found"})


async def main():
    """Run the MCP server."""
    logger.info("Starting Prowler MCP Server")
    logger.info(f"Output directory: {settings.output_dir}")

    # Ensure directories exist
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
