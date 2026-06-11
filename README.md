# dockerfile-vuln-remediator

Scan Dockerfile base images for vulnerabilities and suggest pinned upgrade tags that resolve reported CVEs.

Queries the Red Hat Pyxis API for vulnerabilities in FROM images and recommends newer pinned tags (e.g. `1-1781041605`) that resolve reported CVEs.

## Requirements

- `curl`
- `jq`

## Usage

```bash
./dockerfile-vuln-remedy.sh <DOCKERFILE> [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `DOCKERFILE` | Path to the Dockerfile to scan (required) |

### Options

| Option | Description |
|--------|-------------|
| `--show-all` | Show all severity levels (default: only Critical and High) |
| `--patch` | Generate a patch file (`Dockerfile.patch`) with suggested FROM line changes; apply with: `patch -p0 < Dockerfile.patch` |
| `--help` | Show help message |
| `--version` | Show version information |

### Examples

```bash
./dockerfile-vuln-remedy.sh ./Dockerfile
./dockerfile-vuln-remedy.sh ./Dockerfile --show-all
./dockerfile-vuln-remedy.sh ./Dockerfile --patch
```

## How It Works

1. **Parses FROM statements** from the Dockerfile, including multi-stage builds and `COPY --from` references
2. **Traces dependencies** to identify all images that contribute to the final build
3. **Queries Red Hat Pyxis API** for vulnerability data on each relevant image
4. **Analyzes vulnerabilities** by severity (Critical, High, Medium, Low)
5. **Finds best upgrade tags** by comparing candidate pinned tags against current CVEs
6. **Generates remediation suggestions** with suggested FROM line changes
7. **Optionally generates a patch file** for easy application of suggested changes

## Output

The tool outputs:
- A summary with severity counts (Critical, High, Medium, Low)
- A vulnerability table listing CVEs, affected packages, and images
- Suggested image upgrades with before/after FROM lines
- A patch file (when `--patch` is used)

## Version

1.1.0
