# Testing Guide for GitHub Workflows and Deployment

## Overview

This guide helps you verify that the GitHub workflows and deployment setup are working correctly.

## Pre-deployment Checks

### 1. Validate Workflow Syntax

```bash
# Install yamllint (optional)
pip install yamllint

# Check workflow files
yamllint .github/workflows/*.yml
```

### 2. Test Local Build

```bash
# Test Python package build
python setup.py sdist bdist_wheel

# Verify distributions
pip install twine
twine check dist/*

# Clean up
rm -rf build/ dist/ *.egg-info/
```

### 3. Test Docker Build

```bash
# Build Docker image
docker build -t cybersec-terminal:test .

# Test run
docker run -d --name cybersec-test -p 5000:5000 cybersec-terminal:test

# Check logs
docker logs cybersec-test

# Test access
curl http://localhost:5000/ || echo "Waiting for service..."
sleep 5
curl http://localhost:5000/

# Cleanup
docker stop cybersec-test
docker rm cybersec-test
```

### 4. Test Docker Compose

```bash
# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs

# Test connectivity
curl http://localhost:5000/

# Cleanup
docker-compose down
```

## Testing GitHub Workflows

### 1. Test CI Pipeline

**Trigger:** Push to a branch or create a pull request

```bash
# Create a test branch
git checkout -b test/ci-pipeline

# Make a small change
echo "# Test" >> TEST.md
git add TEST.md
git commit -m "Test CI pipeline"
git push origin test/ci-pipeline

# Create PR on GitHub
# Watch Actions tab for workflow execution
```

**Expected Results:**
- ✅ Test job passes on all Python versions
- ✅ Lint job completes
- ✅ Security scan completes
- ✅ Build artifacts are created

### 2. Test Release Workflow

**Trigger:** Push a version tag

```bash
# Update version in setup.py first
# Then create and push a tag

git tag -a v2.0.0-test -m "Test release workflow"
git push origin v2.0.0-test

# Watch Actions tab for workflow execution
```

**Expected Results:**
- ✅ Build job completes
- ✅ Release packages created
- ✅ GitHub release created with assets
- ✅ Docker images pushed (if enabled)

**Cleanup:**
```bash
# Delete test release on GitHub
# Delete test tag
git tag -d v2.0.0-test
git push origin :refs/tags/v2.0.0-test
```

### 3. Test Docker Workflow

**Trigger:** Push to main or create a tag

```bash
# Push changes to main
git checkout main
git merge test/ci-pipeline
git push origin main

# Watch Actions tab for Docker build
```

**Expected Results:**
- ✅ Docker image builds for multiple platforms
- ✅ Image pushed to GitHub Container Registry
- ✅ SBOM generated
- ✅ Security scan completes

### 4. Test Security Audit

**Trigger:** Manual workflow dispatch

```bash
# Go to GitHub Actions tab
# Select "Dependency and Security Audit" workflow
# Click "Run workflow"
# Select branch and run
```

**Expected Results:**
- ✅ Dependency review completes
- ✅ Security audit runs
- ✅ Reports uploaded as artifacts

### 5. Test Code Quality

**Trigger:** Push to main/develop or create PR

Same as CI Pipeline test, but check for:
- ✅ Code quality metrics in summary
- ✅ Documentation checks pass
- ✅ Link checking completes

## Verification Checklist

### After First Deployment

- [ ] CI Pipeline runs successfully on push
- [ ] Release workflow creates GitHub release
- [ ] Docker images are built and pushed
- [ ] Documentation is accessible
- [ ] Releases include all necessary files:
  - [ ] Source distribution (.tar.gz)
  - [ ] Wheel distribution (.whl)
  - [ ] Platform archives (tar.gz, zip)
  - [ ] Checksums (.sha256 files)
  - [ ] Release notes

### Docker Deployment Verification

- [ ] Docker image pulls successfully
- [ ] Container starts without errors
- [ ] Web interface is accessible
- [ ] Health check passes
- [ ] Container logs show no errors

### Release Package Verification

```bash
# Download release from GitHub
wget https://github.com/morgang213/cs-pro/releases/download/v2.0.0/cybersec-terminal-v2.0.0.tar.gz

# Verify checksum
wget https://github.com/morgang213/cs-pro/releases/download/v2.0.0/cybersec-terminal-v2.0.0.tar.gz.sha256
shasum -a 256 -c cybersec-terminal-v2.0.0.tar.gz.sha256

# Extract and test
tar -xzf cybersec-terminal-v2.0.0.tar.gz
cd cybersec-terminal-v2.0.0/
./install.sh

# Test application
python terminal_web.py &
sleep 5
curl http://localhost:5000/
pkill -f terminal_web.py
```

## Common Issues and Solutions

### Issue: Workflow fails on dependency installation

**Solution:**
```bash
# Update requirements.txt versions
# Test locally first
pip install -r requirements.txt
```

### Issue: Docker build fails

**Solution:**
```bash
# Check Dockerfile syntax
docker build --no-cache -t cybersec-terminal:debug .

# Check build logs for specific errors
# Verify base image is available
docker pull python:3.11-slim
```

### Issue: Release not created

**Solution:**
- Verify tag format: `v2.0.0` (must start with 'v')
- Check repository permissions
- Review workflow logs for errors
- Ensure GITHUB_TOKEN has necessary permissions

### Issue: PyPI publishing fails

**Solution:**
- Verify PYPI_API_TOKEN secret is set
- Check token has upload permissions
- Ensure version not already published
- Test with TestPyPI first

## Manual Testing Checklist

Before creating a production release:

### Python Package
- [ ] Package installs with pip
- [ ] All dependencies install correctly
- [ ] Console scripts work
- [ ] Application starts without errors
- [ ] Web interface loads
- [ ] All tools function correctly

### Docker
- [ ] Image builds successfully
- [ ] Container starts properly
- [ ] Health check passes
- [ ] Web interface accessible
- [ ] All tools work in container
- [ ] Environment variables work
- [ ] Volume mounts work (if used)

### Documentation
- [ ] README.md is complete and accurate
- [ ] CHANGELOG.md is updated
- [ ] Installation instructions work
- [ ] All links are valid
- [ ] API documentation is current

### Security
- [ ] No secrets in code or config
- [ ] Dependencies have no critical vulnerabilities
- [ ] Security scans pass
- [ ] Input validation works
- [ ] Authentication/authorization works (if applicable)

## Performance Testing

### Docker Performance

```bash
# Monitor resource usage
docker stats cybersec-terminal

# Check startup time
time docker run --rm cybersec-terminal:latest python -c "import flask; print('OK')"

# Test memory usage
docker run --memory=256m --name memory-test cybersec-terminal:latest
docker stats --no-stream memory-test
docker rm -f memory-test
```

### Load Testing (if applicable)

```bash
# Install apache bench
apt-get install apache2-utils

# Simple load test
ab -n 100 -c 10 http://localhost:5000/
```

## Monitoring Deployment

### Check GitHub Actions

```bash
# Using GitHub CLI (gh)
gh run list --limit 10
gh run view <run-id>
gh run watch <run-id>
```

### Check Container Registry

```bash
# List images
docker search ghcr.io/morgang213/cs-pro

# Pull specific version
docker pull ghcr.io/morgang213/cs-pro:v2.0.0

# Inspect image
docker inspect ghcr.io/morgang213/cs-pro:latest
```

### Check Release

```bash
# Using GitHub CLI
gh release list
gh release view v2.0.0
gh release download v2.0.0
```

## Automated Testing Script

Create a test script `test-deployment.sh`:

```bash
#!/bin/bash
set -e

echo "Testing Deployment Setup..."

# Test Python package build
echo "Testing package build..."
python setup.py sdist bdist_wheel
twine check dist/*
rm -rf build/ dist/ *.egg-info/

# Test Docker build
echo "Testing Docker build..."
docker build -t cybersec-terminal:test .

# Test Docker run
echo "Testing Docker run..."
docker run -d --name test-container -p 5000:5000 cybersec-terminal:test
sleep 10

# Test connectivity
echo "Testing connectivity..."
curl -f http://localhost:5000/ || (echo "Failed to connect"; exit 1)

# Cleanup
echo "Cleaning up..."
docker stop test-container
docker rm test-container
docker rmi cybersec-terminal:test

echo "All tests passed!"
```

## Continuous Monitoring

Set up monitoring for:

1. **Workflow Success Rate**
   - Track failed builds
   - Monitor test failures
   - Review security scan results

2. **Deployment Health**
   - Container uptime
   - Resource usage
   - Error rates

3. **Release Quality**
   - Download statistics
   - Issue reports
   - User feedback

## Next Steps

After successful testing:

1. Update version to stable release (e.g., v2.0.0)
2. Create production release tag
3. Monitor initial deployment
4. Gather user feedback
5. Plan next iteration

## Support

If you encounter issues during testing:

1. Check workflow logs in GitHub Actions
2. Review error messages carefully
3. Consult documentation:
   - [WORKFLOWS.md](.github/WORKFLOWS.md)
   - [WORKFLOWS_QUICK_REF.md](.github/WORKFLOWS_QUICK_REF.md)
4. Create an issue with:
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Error messages
   - Environment details
