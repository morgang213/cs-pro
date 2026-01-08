# GitHub Workflows Quick Reference

## 🚀 Quick Start

### Creating a New Release

```bash
# 1. Update version in setup.py
# 2. Update CHANGELOG.md
# 3. Commit and push
git add setup.py CHANGELOG.md
git commit -m "Release v2.0.1"
git push origin main

# 4. Create and push tag
git tag -a v2.0.1 -m "Release version 2.0.1"
git push origin v2.0.1
```

### Running Workflows Manually

Go to: **Actions** → Select workflow → **Run workflow**

## 📋 Workflow Status Badges

Add to README.md:

```markdown
![CI Pipeline](https://github.com/morgang213/cs-pro/workflows/CI%20Pipeline/badge.svg)
![Release](https://github.com/morgang213/cs-pro/workflows/Release%20and%20Deploy/badge.svg)
![Security](https://github.com/morgang213/cs-pro/workflows/Dependency%20and%20Security%20Audit/badge.svg)
![Docker](https://github.com/morgang213/cs-pro/workflows/Docker%20Build%20and%20Push/badge.svg)
```

## 🔧 Common Commands

### Docker Deployment

```bash
# Pull and run latest image
docker pull ghcr.io/morgang213/cs-pro:latest
docker run -d -p 5000:5000 ghcr.io/morgang213/cs-pro:latest

# Or use docker-compose
docker-compose up -d
```

### Local Testing

```bash
# Test build locally
python setup.py sdist bdist_wheel

# Test Docker build
docker build -t cybersec-terminal:test .
docker run -p 5000:5000 cybersec-terminal:test
```

## 📊 Workflow Overview

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| CI Pipeline | Push/PR to main/develop | Testing and building |
| Release and Deploy | Git tags (v*.*.*) | Create GitHub releases |
| Security Audit | Weekly / Manual | Security and dependency checks |
| Code Quality | Push/PR to main/develop | Code quality analysis |
| Docker Build | Push to main / Tags | Build and push Docker images |

## 🔐 Required Secrets

Configure in: **Settings** → **Secrets and variables** → **Actions**

| Secret | Required | Purpose |
|--------|----------|---------|
| `GITHUB_TOKEN` | Auto-created | GitHub API access |
| `PYPI_API_TOKEN` | Optional | PyPI package publishing |

## 🎯 Release Checklist

- [ ] Update version in `setup.py`
- [ ] Update `CHANGELOG.md`
- [ ] Commit changes
- [ ] Create git tag
- [ ] Push tag to trigger release workflow
- [ ] Verify GitHub release created
- [ ] Test published packages
- [ ] Update documentation if needed

## 📦 Artifacts

Workflows generate downloadable artifacts:

- **security-reports** (30 days): Security scan results
- **security-audit-reports** (90 days): Dependency audits
- **release-packages** (30 days): Build distributions
- **sbom** (90 days): Software Bill of Materials

Download from: **Actions** → Select run → **Artifacts**

## 🐛 Troubleshooting

### Workflow Failed?

1. Check workflow logs in Actions tab
2. Look for red ❌ marks
3. Expand failed step for details
4. Check for common issues:
   - Syntax errors in code
   - Missing dependencies
   - Version conflicts
   - Network timeouts

### Release Not Created?

- Verify tag format: `v2.0.0` (starts with 'v')
- Check workflow permissions
- Review deploy.yml workflow logs

### Docker Build Failed?

- Check Dockerfile syntax
- Verify base image availability
- Check network connectivity
- Review build logs for errors

## 📚 Full Documentation

For detailed information, see [WORKFLOWS.md](.github/WORKFLOWS.md)

## 🆘 Getting Help

1. Check workflow logs
2. Review documentation
3. Search existing issues
4. Create new issue with:
   - Workflow name
   - Error message
   - Steps to reproduce
