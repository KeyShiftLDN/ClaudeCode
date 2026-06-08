#!/usr/bin/env python3
"""
FFUF MCP Server

A Model Context Protocol server that provides web fuzzing
capabilities using ffuf (Fuzz Faster U Fool).

Tools:
    - ffuf_dir: Directory/file discovery fuzzing
    - ffuf_vhost: Virtual host discovery
    - ffuf_param: Parameter fuzzing
    - ffuf_custom: Custom fuzzing with full control
    - get_fuzz_results: Retrieve previous fuzzing results
    - list_active_scans: Show running scans
    - list_wordlists: List available wordlists
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
logger = logging.getLogger("ffuf-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    output_dir: str = Field(default="/app/output", alias="FFUF_OUTPUT_DIR")
    wordlists_dir: str = Field(default="/app/wordlists", alias="FFUF_WORDLISTS_DIR")
    default_timeout: int = Field(default=600, alias="FFUF_TIMEOUT")
    max_concurrent_scans: int = Field(default=2, alias="FFUF_MAX_CONCURRENT")
    default_threads: int = Field(default=40, alias="FFUF_THREADS")
    default_rate: int = Field(default=0, alias="FFUF_RATE")  # 0 = unlimited

    class Config:
        env_prefix = "FFUF_"


settings = Settings()


class FuzzResult(BaseModel):
    """Model for a single fuzz result."""

    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str | None = None
    redirect_location: str | None = None
    input_value: str | None = None
    position: int | None = None


class ScanResult(BaseModel):
    """Model for scan results."""

    scan_id: str
    target: str
    fuzz_type: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    results: list[FuzzResult] = []
    stats: dict[str, Any] = {}
    error: str | None = None
    raw_output: str | None = None


# In-memory storage for scan results
scan_results: dict[str, ScanResult] = {}
active_scans: set[str] = set()

# Common wordlists
WORDLISTS = {
    "common": "/app/wordlists/common.txt",
    "dirb-common": "/app/wordlists/dirb/common.txt",
    "dirbuster-medium": "/app/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "raft-large-dirs": "/app/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "raft-large-files": "/app/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt",
    "subdomains-top1mil": "/app/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "params-top": "/app/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt",
}


def parse_ffuf_json(output: str) -> list[FuzzResult]:
    """Parse ffuf JSON output."""
    results = []

    try:
        data = json.loads(output)
        for result in data.get("results", []):
            results.append(FuzzResult(
                url=result.get("url", ""),
                status=result.get("status", 0),
                length=result.get("length", 0),
                words=result.get("words", 0),
                lines=result.get("lines", 0),
                content_type=result.get("content-type"),
                redirect_location=result.get("redirectlocation"),
                input_value=result.get("input", {}).get("FUZZ"),
                position=result.get("position"),
            ))
    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing ffuf output: {e}")

    return results


def get_wordlist_path(wordlist: str) -> str:
    """Get full path for a wordlist."""
    if wordlist in WORDLISTS:
        return WORDLISTS[wordlist]
    elif Path(wordlist).exists():
        return wordlist
    elif Path(settings.wordlists_dir, wordlist).exists():
        return str(Path(settings.wordlists_dir, wordlist))
    return wordlist


async def run_ffuf(
    url: str,
    wordlist: str,
    fuzz_type: str = "dir",
    extensions: list[str] | None = None,
    match_codes: list[int] | None = None,
    filter_codes: list[int] | None = None,
    filter_size: int | None = None,
    filter_words: int | None = None,
    threads: int | None = None,
    rate: int | None = None,
    timeout: int | None = None,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    data: str | None = None,
) -> ScanResult:
    """Execute ffuf fuzzing asynchronously."""
    scan_id = str(uuid.uuid4())[:8]
    output_file = Path(settings.output_dir) / f"ffuf_{scan_id}.json"

    result = ScanResult(
        scan_id=scan_id,
        target=url,
        fuzz_type=fuzz_type,
        started_at=datetime.now(),
    )
    scan_results[scan_id] = result
    active_scans.add(scan_id)

    # Build ffuf command
    wordlist_path = get_wordlist_path(wordlist)

    cmd = [
        "ffuf",
        "-u", url,
        "-w", wordlist_path,
        "-o", str(output_file),
        "-of", "json",
        "-t", str(threads or settings.default_threads),
        "-noninteractive",
        "-s",  # Silent mode
    ]

    # Add rate limiting
    if rate or settings.default_rate:
        cmd.extend(["-rate", str(rate or settings.default_rate)])

    # Add extensions for directory fuzzing
    if extensions:
        cmd.extend(["-e", ",".join(extensions)])

    # Add match/filter codes
    if match_codes:
        cmd.extend(["-mc", ",".join(str(c) for c in match_codes)])
    if filter_codes:
        cmd.extend(["-fc", ",".join(str(c) for c in filter_codes)])

    # Add size/word filters
    if filter_size is not None:
        cmd.extend(["-fs", str(filter_size)])
    if filter_words is not None:
        cmd.extend(["-fw", str(filter_words)])

    # Add HTTP method
    if method.upper() != "GET":
        cmd.extend(["-X", method.upper()])

    # Add POST data
    if data:
        cmd.extend(["-d", data])

    # Add custom headers
    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    logger.info(f"Starting {fuzz_type} fuzzing {scan_id} for target: {url}")
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

        # Read output file
        if output_file.exists():
            output_content = output_file.read_text()
            result.raw_output = output_content
            result.results = parse_ffuf_json(output_content)

        # Generate stats
        status_counts = {}
        for r in result.results:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1

        result.stats = {
            "total_results": len(result.results),
            "by_status": status_counts,
            "wordlist": wordlist,
        }

        if process.returncode == 0:
            result.status = "completed"
            logger.info(f"Fuzzing {scan_id} completed: {len(result.results)} results")
        else:
            stderr_text = stderr.decode()
            if result.results:
                result.status = "completed"
            else:
                result.status = "failed"
                result.error = stderr_text
                logger.error(f"Fuzzing {scan_id} failed: {stderr_text}")

    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Fuzzing timed out after {timeout or settings.default_timeout} seconds"
        result.completed_at = datetime.now()
        logger.error(f"Fuzzing {scan_id} timed out")

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()
        logger.exception(f"Fuzzing {scan_id} error: {e}")

    finally:
        active_scans.discard(scan_id)
        scan_results[scan_id] = result

    return result


def format_scan_summary(result: ScanResult) -> dict[str, Any]:
    """Format scan result for response."""
    results_summary = []
    for r in result.results[:100]:  # Limit to 100
        results_summary.append({
            "url": r.url,
            "status": r.status,
            "length": r.length,
            "words": r.words,
            "input": r.input_value,
        })

    return {
        "scan_id": result.scan_id,
        "target": result.target,
        "fuzz_type": result.fuzz_type,
        "status": result.status,
        "stats": result.stats,
        "results": results_summary,
        "error": result.error,
    }


# Create MCP server
app = Server("ffuf-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="ffuf_dir",
            description="Directory and file discovery fuzzing. "
            "Discovers hidden directories, files, and endpoints on web servers.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL with FUZZ keyword (e.g., https://example.com/FUZZ)",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Wordlist to use (common, dirb-common, dirbuster-medium, raft-large-dirs, or path)",
                        "default": "common",
                    },
                    "extensions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "File extensions to append (e.g., php, html, txt)",
                    },
                    "filter_codes": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "HTTP status codes to filter out (e.g., 404, 403)",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads",
                        "default": 40,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="ffuf_vhost",
            description="Virtual host discovery. "
            "Discovers subdomains and virtual hosts by fuzzing the Host header.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL (e.g., https://10.10.10.10)",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Base domain for vhost discovery (e.g., example.com)",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Subdomain wordlist to use",
                        "default": "subdomains-top1mil",
                    },
                    "filter_size": {
                        "type": "integer",
                        "description": "Filter responses by size (to remove default page)",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads",
                        "default": 40,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["url", "domain"],
            },
        ),
        Tool(
            name="ffuf_param",
            description="Parameter fuzzing. "
            "Discovers hidden GET or POST parameters.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL with FUZZ keyword (e.g., https://example.com/page?FUZZ=test)",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Parameter wordlist to use",
                        "default": "params-top",
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST"],
                        "description": "HTTP method",
                        "default": "GET",
                    },
                    "data": {
                        "type": "string",
                        "description": "POST data with FUZZ keyword (e.g., FUZZ=test)",
                    },
                    "filter_size": {
                        "type": "integer",
                        "description": "Filter responses by size",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads",
                        "default": 40,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="ffuf_custom",
            description="Custom fuzzing with full control over all options. "
            "Use FUZZ keyword in URL, headers, or data.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL (use FUZZ keyword where needed)",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Wordlist path or name",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET, POST, PUT, etc.)",
                        "default": "GET",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Custom headers as key-value pairs",
                    },
                    "data": {
                        "type": "string",
                        "description": "Request body data",
                    },
                    "match_codes": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Only show these HTTP status codes",
                    },
                    "filter_codes": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Hide these HTTP status codes",
                    },
                    "filter_size": {
                        "type": "integer",
                        "description": "Filter by response size",
                    },
                    "filter_words": {
                        "type": "integer",
                        "description": "Filter by word count",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Concurrent threads",
                        "default": 40,
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Rate limit (requests per second)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["url", "wordlist"],
            },
        ),
        Tool(
            name="list_wordlists",
            description="List available wordlists for fuzzing.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="get_fuzz_results",
            description="Retrieve results from a previous fuzzing session by scan ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Scan ID returned from a previous scan",
                    },
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="list_active_scans",
            description="List currently running fuzzing sessions.",
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
        if name == "ffuf_dir":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            url = arguments["url"]
            if "FUZZ" not in url:
                url = url.rstrip("/") + "/FUZZ"

            result = await run_ffuf(
                url=url,
                wordlist=arguments.get("wordlist", "common"),
                fuzz_type="directory",
                extensions=arguments.get("extensions"),
                filter_codes=arguments.get("filter_codes", [404]),
                threads=arguments.get("threads"),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "ffuf_vhost":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            domain = arguments["domain"]
            headers = {"Host": f"FUZZ.{domain}"}

            result = await run_ffuf(
                url=arguments["url"],
                wordlist=arguments.get("wordlist", "subdomains-top1mil"),
                fuzz_type="vhost",
                headers=headers,
                filter_size=arguments.get("filter_size"),
                threads=arguments.get("threads"),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "ffuf_param":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_ffuf(
                url=arguments["url"],
                wordlist=arguments.get("wordlist", "params-top"),
                fuzz_type="parameter",
                method=arguments.get("method", "GET"),
                data=arguments.get("data"),
                filter_size=arguments.get("filter_size"),
                threads=arguments.get("threads"),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "ffuf_custom":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_ffuf(
                url=arguments["url"],
                wordlist=arguments["wordlist"],
                fuzz_type="custom",
                method=arguments.get("method", "GET"),
                headers=arguments.get("headers"),
                data=arguments.get("data"),
                match_codes=arguments.get("match_codes"),
                filter_codes=arguments.get("filter_codes"),
                filter_size=arguments.get("filter_size"),
                filter_words=arguments.get("filter_words"),
                threads=arguments.get("threads"),
                rate=arguments.get("rate"),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "list_wordlists":
            available = {}
            for name_key, path in WORDLISTS.items():
                exists = Path(path).exists()
                available[name_key] = {
                    "path": path,
                    "available": exists,
                }

            # Also list files in wordlists directory
            custom = []
            wordlist_path = Path(settings.wordlists_dir)
            if wordlist_path.exists():
                for f in wordlist_path.rglob("*.txt"):
                    custom.append(str(f.relative_to(wordlist_path)))

            return [
                TextContent(
                    type="text",
                    text=json.dumps({
                        "builtin_wordlists": available,
                        "custom_wordlists": custom[:50],
                        "wordlists_directory": settings.wordlists_dir,
                    }, indent=2),
                )
            ]

        elif name == "get_fuzz_results":
            scan_id = arguments["scan_id"]
            result = scan_results.get(scan_id)

            if result:
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(format_scan_summary(result), indent=2),
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
                    "fuzz_type": scan_results[scan_id].fuzz_type,
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
            result_count = len(result.results)
            resources.append(
                Resource(
                    uri=f"ffuf://results/{scan_id}",
                    name=f"Fuzz Results: {result.target} ({result_count} results)",
                    description=f"{result.fuzz_type} fuzzing completed at {result.completed_at}",
                    mimeType="application/json",
                )
            )

    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource."""
    if uri.startswith("ffuf://results/"):
        scan_id = uri.replace("ffuf://results/", "")
        result = scan_results.get(scan_id)
        if result:
            return json.dumps(format_scan_summary(result), indent=2)

    return json.dumps({"error": "Resource not found"})


async def main():
    """Run the MCP server."""
    logger.info("Starting FFUF MCP Server")
    logger.info(f"Output directory: {settings.output_dir}")
    logger.info(f"Wordlists directory: {settings.wordlists_dir}")

    # Ensure directories exist
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.wordlists_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
