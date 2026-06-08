# Trivy MCP Server

A Model Context Protocol server that provides security scanning capabilities using [Aqua Security's Trivy](https://github.com/aquasecurity/trivy) scanner.

> **Note**: This MCP server uses the official [Aqua Security trivy-mcp plugin](https://github.com/aquasecurity/trivy-mcp).

## Tools

| Tool | Description |
|------|-------------|
| `trivy_scan_image` | Scan container images for vulnerabilities |
| `trivy_scan_filesystem` | Scan filesystem/repository for dependency vulnerabilities |
| `trivy_scan_config` | Scan IaC files (Terraform, Dockerfile, K8s) for misconfigurations |
| `trivy_generate_sbom` | Generate Software Bill of Materials (SBOM) |
| `get_scan_results` | Retrieve results from a previous scan |
| `list_active_scans` | Show currently running scans |

## Features

- **Container Image Scanning**: Detect vulnerabilities in Docker images from any registry
- **Filesystem Scanning**: Find vulnerable dependencies in package manifests
- **IaC Scanning**: Detect misconfigurations in Terraform, Kubernetes, Dockerfile, etc.
- **SBOM Generation**: Create CycloneDX or SPDX format SBOMs
- **Severity Filtering**: Filter results by UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL
- **Concurrent Scan Management**: Track and limit concurrent scans

## Docker

### Build

```bash
docker build -t trivy-mcp .
```

### Run

```bash
docker run --rm -i trivy-mcp
```

### With Docker socket (for local image scanning)

```bash
docker run --rm -i \
  -v /var/run/docker.sock:/var/run/docker.sock \
  trivy-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "trivy": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "trivy-mcp"
      ]
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIVY_OUTPUT_DIR` | `/app/output` | Directory for scan results |
| `TRIVY_CACHE_DIR` | `/home/mcpuser/.cache/trivy` | Trivy database cache |
| `TRIVY_TIMEOUT` | `600` | Default scan timeout (seconds) |
| `TRIVY_MAX_CONCURRENT` | `2` | Maximum concurrent scans |

## Example Usage

### Scan a container image

```
Scan the python:3.12-slim image for HIGH and CRITICAL vulnerabilities
```

### Scan IaC files

```
Check my Terraform files in /path/to/terraform for security misconfigurations
```

### Generate SBOM

```
Generate a CycloneDX SBOM for the nginx:latest image
```

## Security Notice

This tool is designed for authorized security testing only. Always ensure you have proper authorization before scanning any systems or images you do not own.

## License

MIT
