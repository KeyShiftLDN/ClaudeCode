#!/usr/bin/env python3
"""
Trivy MCP Server

A Model Context Protocol server that provides security scanning
capabilities using Aqua Security's Trivy scanner.

Tools:
    - trivy_scan_image: Scan container images for vulnerabilities
    - trivy_scan_filesystem: Scan filesystem/repository for vulnerabilities
    - trivy_scan_sbom: Generate SBOM (Software Bill of Materials)
    - trivy_scan_config: Scan IaC files for misconfigurations
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
logger = logging.getLogger("trivy-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    output_dir: str = Field(default="/app/output", alias="TRIVY_OUTPUT_DIR")
    cache_dir: str = Field(default="/home/mcpuser/.cache/trivy", alias="TRIVY_CACHE_DIR")
    default_timeout: int = Field(default=600, alias="TRIVY_TIMEOUT")
    max_concurrent_scans: int = Field(default=2, alias="TRIVY_MAX_CONCURRENT")

    class Config:
        env_prefix = "TRIVY_"


settings = Settings()


class Vulnerability(BaseModel):
    """Model for a single vulnerability."""

    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str | None = None
    severity: str
    title: str | None = None
    description: str | None = None
    references: list[str] = []
    cvss_score: float | None = None


class Misconfiguration(BaseModel):
    """Model for a misconfiguration finding."""

    misconfig_id: str
    avd_id: str | None = None
    type: str
    title: str
    description: str | None = None
    message: str | None = None
    severity: str
    resolution: str | None = None


class ScanResult(BaseModel):
    """Model for scan results."""

    scan_id: str
    target: str
    scan_type: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    vulnerabilities: list[Vulnerability] = []
    misconfigurations: list[Misconfiguration] = []
    stats: dict[str, Any] = {}
    error: str | None = None
    raw_output: str | None = None


# In-memory storage for scan results
scan_results: dict[str, ScanResult] = {}
active_scans: set[str] = set()

SEVERITY_LEVELS = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SCAN_TYPES = ["image", "filesystem", "repo", "config", "sbom"]


def parse_trivy_json(output: str, scan_type: str) -> tuple[list[Vulnerability], list[Misconfiguration]]:
    """Parse trivy JSON output into findings."""
    vulnerabilities = []
    misconfigurations = []

    try:
        data = json.loads(output)
        results = data.get("Results", [])

        for result in results:
            # Parse vulnerabilities
            for vuln in result.get("Vulnerabilities", []):
                vulnerabilities.append(Vulnerability(
                    vuln_id=vuln.get("VulnerabilityID", "unknown"),
                    pkg_name=vuln.get("PkgName", "unknown"),
                    installed_version=vuln.get("InstalledVersion", "unknown"),
                    fixed_version=vuln.get("FixedVersion"),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    title=vuln.get("Title"),
                    description=vuln.get("Description"),
                    references=vuln.get("References", [])[:5],  # Limit refs
                    cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                ))

            # Parse misconfigurations
            for misconfig in result.get("Misconfigurations", []):
                misconfigurations.append(Misconfiguration(
                    misconfig_id=misconfig.get("ID", "unknown"),
                    avd_id=misconfig.get("AVDID"),
                    type=misconfig.get("Type", "unknown"),
                    title=misconfig.get("Title", "unknown"),
                    description=misconfig.get("Description"),
                    message=misconfig.get("Message"),
                    severity=misconfig.get("Severity", "UNKNOWN"),
                    resolution=misconfig.get("Resolution"),
                ))

    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing trivy output: {e}")

    return vulnerabilities, misconfigurations


async def run_trivy_scan(
    target: str,
    scan_type: str = "image",
    severity: list[str] | None = None,
    ignore_unfixed: bool = False,
    timeout: int | None = None,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Execute a trivy scan asynchronously."""
    scan_id = str(uuid.uuid4())[:8]
    output_file = Path(settings.output_dir) / f"scan_{scan_id}.json"

    result = ScanResult(
        scan_id=scan_id,
        target=target,
        scan_type=scan_type,
        started_at=datetime.now(),
    )
    scan_results[scan_id] = result
    active_scans.add(scan_id)

    # Build trivy command
    cmd = [
        "trivy",
        scan_type,  # image, filesystem, repo, config
        target,
        "--format", "json",
        "--output", str(output_file),
        "--cache-dir", settings.cache_dir,
    ]

    # Add severity filter
    if severity:
        cmd.extend(["--severity", ",".join(severity)])

    # Ignore unfixed vulnerabilities
    if ignore_unfixed:
        cmd.append("--ignore-unfixed")

    # Add extra arguments
    if extra_args:
        cmd.extend(extra_args)

    logger.info(f"Starting {scan_type} scan {scan_id} for target: {target}")
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

        # Read output file if exists
        if output_file.exists():
            output_content = output_file.read_text()
            result.raw_output = output_content
            result.vulnerabilities, result.misconfigurations = parse_trivy_json(
                output_content, scan_type
            )
        else:
            # Try parsing stdout
            stdout_text = stdout.decode()
            result.raw_output = stdout_text

        # Generate stats
        severity_counts = {}
        for vuln in result.vulnerabilities:
            sev = vuln.severity.upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        misconfig_counts = {}
        for misconfig in result.misconfigurations:
            sev = misconfig.severity.upper()
            misconfig_counts[sev] = misconfig_counts.get(sev, 0) + 1

        result.stats = {
            "total_vulnerabilities": len(result.vulnerabilities),
            "vulnerabilities_by_severity": severity_counts,
            "total_misconfigurations": len(result.misconfigurations),
            "misconfigurations_by_severity": misconfig_counts,
        }

        if process.returncode == 0:
            result.status = "completed"
            logger.info(
                f"Scan {scan_id} completed: "
                f"{len(result.vulnerabilities)} vulnerabilities, "
                f"{len(result.misconfigurations)} misconfigurations"
            )
        else:
            result.status = "completed"  # Trivy returns non-zero when findings exist
            stderr_text = stderr.decode()
            if "error" in stderr_text.lower():
                result.status = "failed"
                result.error = stderr_text
                logger.error(f"Scan {scan_id} failed: {result.error}")

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


async def generate_sbom(
    target: str,
    sbom_format: str = "cyclonedx",
    timeout: int | None = None,
) -> ScanResult:
    """Generate SBOM for a target."""
    scan_id = str(uuid.uuid4())[:8]
    output_file = Path(settings.output_dir) / f"sbom_{scan_id}.json"

    result = ScanResult(
        scan_id=scan_id,
        target=target,
        scan_type="sbom",
        started_at=datetime.now(),
    )
    scan_results[scan_id] = result
    active_scans.add(scan_id)

    # Build trivy sbom command
    cmd = [
        "trivy",
        "image",
        target,
        "--format", sbom_format,
        "--output", str(output_file),
        "--cache-dir", settings.cache_dir,
    ]

    logger.info(f"Generating SBOM {scan_id} for target: {target}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        await asyncio.wait_for(
            process.communicate(),
            timeout=float(timeout or settings.default_timeout),
        )

        result.completed_at = datetime.now()

        if output_file.exists():
            result.raw_output = output_file.read_text()
            result.status = "completed"
            result.stats = {"sbom_format": sbom_format, "output_file": str(output_file)}
            logger.info(f"SBOM {scan_id} generated successfully")
        else:
            result.status = "failed"
            result.error = "SBOM generation failed - no output file"

    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"SBOM generation timed out after {timeout or settings.default_timeout} seconds"
        result.completed_at = datetime.now()

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()
        logger.exception(f"SBOM {scan_id} error: {e}")

    finally:
        active_scans.discard(scan_id)
        scan_results[scan_id] = result

    return result


def format_scan_summary(result: ScanResult) -> dict[str, Any]:
    """Format scan result for response."""
    vulns_summary = []
    for vuln in result.vulnerabilities[:50]:  # Limit to 50
        vulns_summary.append({
            "vuln_id": vuln.vuln_id,
            "pkg_name": vuln.pkg_name,
            "severity": vuln.severity,
            "installed_version": vuln.installed_version,
            "fixed_version": vuln.fixed_version,
            "title": vuln.title,
        })

    misconfigs_summary = []
    for misconfig in result.misconfigurations[:50]:
        misconfigs_summary.append({
            "id": misconfig.misconfig_id,
            "type": misconfig.type,
            "severity": misconfig.severity,
            "title": misconfig.title,
            "message": misconfig.message,
        })

    return {
        "scan_id": result.scan_id,
        "target": result.target,
        "scan_type": result.scan_type,
        "status": result.status,
        "stats": result.stats,
        "vulnerabilities": vulns_summary,
        "misconfigurations": misconfigs_summary,
        "error": result.error,
    }


# Create MCP server
app = Server("trivy-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="trivy_scan_image",
            description="Scan a container image for vulnerabilities. "
            "Supports Docker Hub, ECR, GCR, and local images.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image": {
                        "type": "string",
                        "description": "Image to scan (e.g., python:3.12, nginx:latest, ghcr.io/org/image:tag)",
                    },
                    "severity": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": SEVERITY_LEVELS,
                        },
                        "description": "Filter by severity levels (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)",
                    },
                    "ignore_unfixed": {
                        "type": "boolean",
                        "description": "Ignore vulnerabilities without a fix",
                        "default": False,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["image"],
            },
        ),
        Tool(
            name="trivy_scan_filesystem",
            description="Scan a filesystem path or git repository for vulnerabilities "
            "in dependencies (package-lock.json, requirements.txt, go.mod, etc.).",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Filesystem path or git URL to scan",
                    },
                    "severity": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": SEVERITY_LEVELS,
                        },
                        "description": "Filter by severity levels",
                    },
                    "ignore_unfixed": {
                        "type": "boolean",
                        "description": "Ignore vulnerabilities without a fix",
                        "default": False,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="trivy_scan_config",
            description="Scan IaC files (Terraform, Dockerfile, Kubernetes YAML, etc.) "
            "for misconfigurations and security issues.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to IaC files or directory",
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
                        "description": "Scan timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="trivy_generate_sbom",
            description="Generate a Software Bill of Materials (SBOM) for an image. "
            "Outputs in CycloneDX or SPDX format.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image": {
                        "type": "string",
                        "description": "Image to generate SBOM for",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["cyclonedx", "spdx", "spdx-json"],
                        "description": "SBOM output format",
                        "default": "cyclonedx",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["image"],
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
                    "include_raw": {
                        "type": "boolean",
                        "description": "Include raw trivy output",
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
        if name == "trivy_scan_image":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_trivy_scan(
                target=arguments["image"],
                scan_type="image",
                severity=arguments.get("severity"),
                ignore_unfixed=arguments.get("ignore_unfixed", False),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "trivy_scan_filesystem":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_trivy_scan(
                target=arguments["path"],
                scan_type="filesystem",
                severity=arguments.get("severity"),
                ignore_unfixed=arguments.get("ignore_unfixed", False),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "trivy_scan_config":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_trivy_scan(
                target=arguments["path"],
                scan_type="config",
                severity=arguments.get("severity"),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "trivy_generate_sbom":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await generate_sbom(
                target=arguments["image"],
                sbom_format=arguments.get("format", "cyclonedx"),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "get_scan_results":
            scan_id = arguments["scan_id"]
            result = scan_results.get(scan_id)

            if result:
                output = format_scan_summary(result)
                if arguments.get("include_raw") and result.raw_output:
                    output["raw_output"] = result.raw_output[:10000]  # Limit size
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
                    "target": scan_results[scan_id].target,
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
            vuln_count = len(result.vulnerabilities)
            misconfig_count = len(result.misconfigurations)
            resources.append(
                Resource(
                    uri=f"trivy://results/{scan_id}",
                    name=f"Scan Results: {result.target} ({vuln_count} vulns, {misconfig_count} misconfigs)",
                    description=f"{result.scan_type} scan completed at {result.completed_at}",
                    mimeType="application/json",
                )
            )

    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource."""
    if uri.startswith("trivy://results/"):
        scan_id = uri.replace("trivy://results/", "")
        result = scan_results.get(scan_id)
        if result:
            return json.dumps(format_scan_summary(result), indent=2)

    return json.dumps({"error": "Resource not found"})


async def main():
    """Run the MCP server."""
    logger.info("Starting Trivy MCP Server")
    logger.info(f"Output directory: {settings.output_dir}")
    logger.info(f"Cache directory: {settings.cache_dir}")

    # Ensure directories exist
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.cache_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
