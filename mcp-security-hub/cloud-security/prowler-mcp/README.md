# Prowler MCP Server

A Model Context Protocol server that provides cloud security assessment capabilities using [Prowler](https://github.com/prowler-cloud/prowler) for AWS, Azure, GCP, and Kubernetes.

## Tools

| Tool | Description |
|------|-------------|
| `prowler_scan` | Run security assessment on cloud provider |
| `prowler_compliance` | Check against compliance frameworks (CIS, PCI-DSS, HIPAA, etc.) |
| `list_checks` | List available security checks |
| `list_compliance_frameworks` | List available compliance frameworks |
| `get_scan_results` | Retrieve results from a previous scan |
| `list_active_scans` | Show currently running scans |

## Supported Cloud Providers

- **AWS** - Amazon Web Services
- **Azure** - Microsoft Azure
- **GCP** - Google Cloud Platform
- **Kubernetes** - Kubernetes clusters

## Compliance Frameworks

### AWS
- CIS AWS Foundations Benchmark (1.4, 1.5, 2.0)
- AWS Foundational Security Best Practices
- PCI DSS 3.2.1
- HIPAA
- SOC 2
- GDPR
- NIST 800-53
- NIST 800-171

### Azure
- CIS Azure Foundations Benchmark (1.0, 2.0)
- Azure Security Benchmark

### GCP
- CIS GCP Foundations Benchmark (1.0, 2.0)

### Kubernetes
- CIS Kubernetes Benchmark (1.6, 1.7)

## Docker

### Build

```bash
docker build -t prowler-mcp .
```

### Run with AWS credentials

```bash
docker run --rm -i \
  -e AWS_ACCESS_KEY_ID=your_key \
  -e AWS_SECRET_ACCESS_KEY=your_secret \
  -e AWS_DEFAULT_REGION=us-east-1 \
  prowler-mcp
```

### Run with AWS profile

```bash
docker run --rm -i \
  -v ~/.aws:/home/mcpuser/.aws:ro \
  -e AWS_PROFILE=your_profile \
  prowler-mcp
```

### Run with Azure credentials

```bash
docker run --rm -i \
  -e AZURE_CLIENT_ID=your_client_id \
  -e AZURE_CLIENT_SECRET=your_secret \
  -e AZURE_TENANT_ID=your_tenant_id \
  -e AZURE_SUBSCRIPTION_ID=your_subscription_id \
  prowler-mcp
```

### Run with GCP credentials

```bash
docker run --rm -i \
  -v /path/to/service-account.json:/app/gcp-creds.json:ro \
  -e GOOGLE_APPLICATION_CREDENTIALS=/app/gcp-creds.json \
  prowler-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "prowler": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "~/.aws:/home/mcpuser/.aws:ro",
        "-e", "AWS_PROFILE=default",
        "prowler-mcp"
      ]
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROWLER_OUTPUT_DIR` | `/app/output` | Directory for scan results |
| `PROWLER_TIMEOUT` | `1800` | Default timeout (30 minutes) |
| `PROWLER_MAX_CONCURRENT` | `1` | Maximum concurrent scans |

### AWS Credentials
| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `AWS_DEFAULT_REGION` | Default AWS region |
| `AWS_PROFILE` | AWS profile name (when using ~/.aws) |

### Azure Credentials
| Variable | Description |
|----------|-------------|
| `AZURE_CLIENT_ID` | Azure service principal client ID |
| `AZURE_CLIENT_SECRET` | Azure service principal secret |
| `AZURE_TENANT_ID` | Azure tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID |

### GCP Credentials
| Variable | Description |
|----------|-------------|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account JSON |

## Example Usage

### Run AWS security assessment

```
Run a security scan on my AWS account focusing on S3 and IAM services
```

### Check CIS compliance

```
Check my AWS environment against CIS 2.0 benchmark
```

### Scan specific regions

```
Scan AWS security in us-east-1 and eu-west-1 regions only
```

### Check PCI-DSS compliance

```
Run a PCI-DSS compliance check on my AWS account
```

### List available checks

```
What security checks are available for AWS S3?
```

## Security Notice

- Prowler requires cloud credentials with read permissions
- Use least-privilege access (read-only roles)
- Never commit credentials to version control
- Results may contain sensitive information

## Recommended IAM Policies

### AWS
Use the `SecurityAudit` managed policy or Prowler's recommended policy.

### Azure
Use the `Reader` role at subscription scope.

### GCP
Use the `Viewer` role at project scope.

## License

MIT
