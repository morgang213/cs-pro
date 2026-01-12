# GitHub Actions Workflows

This directory contains GitHub Actions workflows for automating the build, test, and release process of the CyberSec Terminal project.

## Workflows

### 1. Build and Release (`release.yml`)

**Triggers:**
- When a version tag is pushed (e.g., `v2.0.0`, `v2.1.0`)
- Manual workflow dispatch with version input

**What it does:**
1. Builds Python packages (wheel and source distribution)
2. Creates release archives (`.tar.gz` for Linux/macOS, `.zip` for Windows)
3. Generates SHA-256 checksums for all artifacts
4. Creates a GitHub Release with all artifacts attached
5. Automatically tags the release if triggered manually

**Usage:**

Option 1 - Push a tag:
```bash
git tag -a v2.0.0 -m "Release v2.0.0"
git push origin v2.0.0
```

Option 2 - Manual trigger:
1. Go to Actions tab in GitHub
2. Select "Build and Release" workflow
3. Click "Run workflow"
4. Enter the version number (e.g., `2.0.0`)
5. Click "Run workflow"

**Outputs:**
- GitHub Release with the following artifacts:
  - `cybersec-terminal-v{version}.tar.gz` + checksum
  - `cybersec-terminal-v{version}.zip` + checksum
  - `cybersec_terminal-{version}-py3-none-any.whl` + checksum
  - `cybersec_terminal-{version}.tar.gz` + checksum

### 2. Publish to PyPI (`publish-pypi.yml`)

**Triggers:**
- When a GitHub Release is published
- Manual workflow dispatch (publishes to Test PyPI)

**What it does:**
1. Builds Python packages
2. Validates package with `twine check`
3. Publishes to PyPI (on release) or Test PyPI (on manual trigger)

**Setup:**
To enable PyPI publishing, add the following secrets to your repository:
- `PYPI_API_TOKEN` - Token from https://pypi.org/manage/account/token/
- `TEST_PYPI_API_TOKEN` - Token from https://test.pypi.org/manage/account/token/ (optional)

**Usage:**
- Automatically runs when you publish a GitHub Release
- For testing: Go to Actions → "Publish to PyPI" → Run workflow

### 3. CI - Build and Test (`ci.yml`)

**Triggers:**
- Pull requests to main branch
- Pushes to main branch
- Manual workflow dispatch

**What it does:**
1. Tests package building on multiple platforms (Ubuntu, Windows, macOS)
2. Tests across Python versions 3.7-3.12
3. Verifies package installation
4. Checks package quality with `twine check`

**Usage:**
Runs automatically on PRs and pushes. No manual intervention needed.

## Complete Release Process

### For a New Release:

1. **Update version** in `setup.py`:
   ```python
   version="2.1.0",
   ```

2. **Create/update release notes** (optional):
   - Create `RELEASE_NOTES_v2.1.0.md` with release details
   - Or the workflow will generate basic release notes

3. **Commit and push changes**:
   ```bash
   git add setup.py RELEASE_NOTES_v2.1.0.md
   git commit -m "Bump version to 2.1.0"
   git push
   ```

4. **Trigger release**:
   
   Option A - Tag and push:
   ```bash
   git tag -a v2.1.0 -m "Release v2.1.0"
   git push origin v2.1.0
   ```
   
   Option B - Manual workflow:
   - Go to Actions → "Build and Release" → Run workflow
   - Enter version: `2.1.0`

5. **Publish the release**:
   - Go to Releases in GitHub
   - The release will be created automatically
   - Edit if needed and ensure it's published (not draft)

6. **PyPI publishing** (optional):
   - If `PYPI_API_TOKEN` is configured, package will be published automatically
   - Otherwise, publish manually with: `twine upload dist/*`

## Permissions

The workflows use the following permissions:
- `contents: write` - For creating releases and tags
- `contents: read` - For reading repository content

These are handled automatically by GitHub Actions.

## Troubleshooting

### Release workflow fails to create tag
- The tag may already exist. Delete it first: `git push --delete origin v2.0.0`

### PyPI publish fails
- Ensure `PYPI_API_TOKEN` secret is set correctly
- Check that the version doesn't already exist on PyPI
- Version numbers cannot be reused on PyPI

### Build fails on specific Python version
- Check `requirements.txt` for compatibility issues
- Some dependencies may not support all Python versions

## Security Notes

- Never commit API tokens or secrets to the repository
- Use GitHub Secrets for all sensitive credentials
- Workflow files are public and can be viewed by anyone
- The workflows run in isolated environments with limited permissions
