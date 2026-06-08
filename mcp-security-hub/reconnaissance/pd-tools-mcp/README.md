# PD-Tools MCP Server

A Dockerized wrapper for [pd-tools-mcp](https://github.com/intelligent-ears/pd-tools-mcp) that provides access to ProjectDiscovery security tools.

## Included Tools

| Tool | Description |
|------|-------------|
| **subfinder** | Fast passive subdomain enumeration |
| **httpx** | HTTP probing and fingerprinting |
| **katana** | Next-generation web crawler |
| **nuclei** | Vulnerability scanner with templates |
| **dnsx** | Fast DNS toolkit |
| **naabu** | Fast port scanner |

## Features

This is a wrapper around the community pd-tools-mcp that:
- Bundles all ProjectDiscovery tools in a single container
- Pre-installs tools from latest releases
- Follows security hardening best practices
- Ready for Docker Compose orchestration

## Docker

### Build

```bash
docker build -t pd-tools-mcp .
```

### Run

```bash
docker run --rm -i pd-tools-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "pd-tools": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "pd-tools-mcp"]
    }
  }
}
```

## Example Usage

### Subdomain enumeration

```
Find all subdomains of example.com using subfinder
```

### HTTP probing

```
Probe these hosts with httpx to find live web servers
```

### Web crawling

```
Crawl https://example.com with katana to discover endpoints
```

### Vulnerability scanning

```
Run nuclei scan against https://example.com for CVEs
```

### DNS reconnaissance

```
Resolve DNS records for these domains using dnsx
```

### Port scanning

```
Scan ports on 192.168.1.1 using naabu
```

## Upstream

This is a Docker wrapper for:
- Repository: [intelligent-ears/pd-tools-mcp](https://github.com/intelligent-ears/pd-tools-mcp)
- Tools: [ProjectDiscovery](https://projectdiscovery.io/)

## Security Notice

These tools are designed for authorized security testing only. Always ensure you have permission before scanning any systems you do not own.

## License

MIT
