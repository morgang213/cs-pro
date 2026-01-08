# GitHub Workflows Documentation

## Overview

This repository includes comprehensive GitHub Actions workflows for continuous integration, deployment, security scanning, and code quality checks.

## Workflows

### 1. CI Pipeline (`ci.yml`)

**Trigger:** Push to `main` or `develop` branches, Pull requests

**Purpose:** Automated testing and building

**Jobs:**
- **Test and Build**: Tests the application on Python 3.7-3.12
  - Installs dependencies
  - Verifies imports
  - Builds packages
  - Validates distributions

- **Lint**: Code quality checks
  - Runs flake8 for syntax errors
  - Checks code style compliance

- **Security**: Security scanning
  - Runs safety check for vulnerable dependencies
  - Runs bandit for code security issues
  - Generates security reports

### 2. Release and Deploy (`deploy.yml`)

**Trigger:** Git tags matching `v*.*.*` pattern, Manual workflow dispatch

**Purpose:** Automated release creation and deployment

**Jobs:**
- **Build Release Packages**:
  - Builds Python packages (wheel and source distribution)
  - Creates platform-specific archives (tar.gz for Linux/macOS, zip for Windows)
  - Generates SHA-256 checksums
  - Creates installation guide

- **Create GitHub Release**:
  - Generates comprehensive release notes
  - Creates GitHub release with assets
  - Uploads all distribution files and checksums

- **Publish to PyPI** (optional):
  - Publishes package to PyPI
  - Requires `PYPI_API_TOKEN` secret

**Required Secrets:**
- `PYPI_API_TOKEN` (optional, for PyPI publishing)

**How to Create a Release:**
```bash
# Create and push a tag
git tag -a v2.0.1 -m "Release version 2.0.1"
git push origin v2.0.1

# Or trigger manually via GitHub UI
# Actions -> Release and Deploy -> Run workflow
```

### 3. Security Audit (`security-audit.yml`)

**Trigger:** Weekly on Mondays at 9:00 UTC, Manual dispatch, Changes to dependencies

**Purpose:** Regular security and dependency audits

**Jobs:**
- **Dependency Review**: Reviews dependencies in pull requests
- **Security Audit**:
  - Runs pip-audit for vulnerability scanning
  - Runs safety check for known vulnerabilities
  - Runs bandit for code security analysis
  - Generates detailed reports

- **Update Dependencies**:
  - Checks for outdated dependencies
  - Creates issues for updates when found

### 4. Code Quality and Documentation (`code-quality.yml`)

**Trigger:** Push to `main` or `develop`, Pull requests

**Purpose:** Maintain code quality and documentation standards

**Jobs:**
- **Code Quality Analysis**:
  - Checks formatting with black
  - Checks import sorting with isort
  - Runs comprehensive flake8 checks
  - Runs pylint analysis
  - Calculates code complexity with radon
  - Measures maintainability index

- **Documentation Check**:
  - Verifies required documentation files exist
  - Checks README completeness
  - Finds TODO/FIXME comments

- **Link Checker**: Validates links in markdown files
- **Spell Check**: Checks spelling in documentation

### 5. Docker Build and Push (`docker.yml`)

**Trigger:** Push to `main`, Git tags, Pull requests, Manual dispatch

**Purpose:** Build and publish Docker images

**Jobs:**
- **Build and Push Docker Image**:
  - Builds multi-platform images (amd64, arm64)
  - Pushes to GitHub Container Registry
  - Generates Software Bill of Materials (SBOM)
  - Scans for vulnerabilities
  - Uploads scan results

**Docker Images Published to:**
- `ghcr.io/morgang213/cs-pro:latest`
- `ghcr.io/morgang213/cs-pro:v2.0.0`
- `ghcr.io/morgang213/cs-pro:main`

## Configuration Files

### `.github/markdown-link-check-config.json`
Configuration for link checking in documentation:
- Ignores localhost URLs
- Sets retry policies
- Defines valid status codes

### `.github/spellcheck-config.yml`
Configuration for spell checking:
- Language: English
- Checks markdown files
- Ignores code blocks

## Deployment Instructions

### Standard Release Process

1. **Update version** in `setup.py`
2. **Update CHANGELOG.md** with release notes
3. **Commit changes**:
   ```bash
   git add setup.py CHANGELOG.md
   git commit -m "Prepare release v2.0.1"
   git push origin main
   ```
4. **Create and push tag**:
   ```bash
   git tag -a v2.0.1 -m "Release version 2.0.1"
   git push origin v2.0.1
   ```
5. **Monitor workflow**: Check Actions tab for progress
6. **Verify release**: Check Releases page for new release

### Docker Deployment

#### Local Build and Run:
```bash
# Build image
docker build -t cybersec-terminal:local .

# Run container
docker run -d -p 5000:5000 cybersec-terminal:local
```

#### Using Docker Compose:
```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

#### Using Published Image:
```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/morgang213/cs-pro:latest

# Run container
docker run -d -p 5000:5000 ghcr.io/morgang213/cs-pro:latest

# Access at http://localhost:5000
```

### Manual PyPI Publishing

If automatic PyPI publishing fails or is not configured:

```bash
# Build distributions
python setup.py sdist bdist_wheel

# Upload to PyPI
twine upload dist/*
```

## Environment Variables

### Optional API Keys
Set these for enhanced functionality:
```bash
export IPINFO_TOKEN=your_ipinfo_token
export VIRUSTOTAL_API_KEY=your_virustotal_key
export ABUSEIPDB_API_KEY=your_abuseipdb_key
```

### Docker Environment
Use `.env` file for Docker Compose:
```bash
# .env file
IPINFO_TOKEN=your_token_here
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

## Monitoring and Troubleshooting

### View Workflow Status
1. Go to repository on GitHub
2. Click "Actions" tab
3. Select workflow to view runs
4. Click on run to see details

### Common Issues

**Issue: Build fails on Python version**
- Check compatibility in `setup.py`
- Update `classifiers` and `python_requires`

**Issue: PyPI publishing fails**
- Verify `PYPI_API_TOKEN` secret is set
- Check token has correct permissions
- Ensure version number is not already published

**Issue: Docker build fails**
- Check Dockerfile syntax
- Verify base image availability
- Review build logs for specific errors

**Issue: Security scan finds vulnerabilities**
- Review security reports in artifacts
- Update vulnerable dependencies
- Check if false positives can be suppressed

### Artifacts

Workflows generate artifacts that are retained for 30-90 days:
- **security-reports**: Security scan results
- **security-audit-reports**: Dependency audit reports
- **release-packages**: Build artifacts
- **sbom**: Software Bill of Materials

Access artifacts from the workflow run page in GitHub Actions.

## Best Practices

1. **Always test locally** before pushing tags
2. **Review workflow runs** after deployment
3. **Keep dependencies updated** using security-audit workflow
4. **Monitor security reports** regularly
5. **Use semantic versioning** for tags (v2.0.0, v2.0.1, etc.)
6. **Update CHANGELOG.md** with each release
7. **Test Docker images** before deploying to production

## Security Considerations

- Secrets are never exposed in logs
- Docker images run as non-root user
- Security scans run automatically
- Dependencies are regularly audited
- SBOM is generated for compliance

## Maintenance

### Weekly Tasks
- Review security audit results (automated)
- Check for dependency updates (automated)

### Release Tasks
- Update version numbers
- Update CHANGELOG.md
- Create and push tags
- Verify release creation
- Test published packages

### Monthly Tasks
- Review and close completed TODO items
- Update documentation
- Review and address security issues

## Support

For workflow issues:
1. Check workflow logs in Actions tab
2. Review this documentation
3. Create an issue with workflow details
4. Include error messages and logs

## References

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Python Packaging Guide](https://packaging.python.org/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Semantic Versioning](https://semver.org/)
