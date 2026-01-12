# Quick Start Guide - GitHub Deployment

This guide will help you create your first automated release using the new GitHub Actions workflows.

## Prerequisites

✅ The GitHub Actions workflows are now set up in `.github/workflows/`
✅ Your repository is ready for release

## Create Your First Release

### Option 1: Tag-Based Release (Recommended)

This is the standard approach for version releases:

```bash
# 1. Make sure you're on the main branch and up to date
git checkout main
git pull

# 2. Ensure version in setup.py matches your desired release
# Edit setup.py if needed:
#   version="2.0.0",

# 3. Commit any final changes
git add setup.py
git commit -m "Bump version to 2.0.0"
git push

# 4. Create and push a version tag
git tag -a v2.0.0 -m "Release v2.0.0 - First automated release"
git push origin v2.0.0

# 5. GitHub Actions will automatically:
#    - Build packages
#    - Create release archives
#    - Generate checksums
#    - Create a GitHub Release with all artifacts
```

### Option 2: Manual Workflow Dispatch

Use this for testing or when you don't want to create a tag first:

1. Go to your repository on GitHub
2. Click on **Actions** tab
3. Select **"Build and Release"** workflow from the left sidebar
4. Click **"Run workflow"** button (top right)
5. Enter the version number (e.g., `2.0.0`)
6. Click **"Run workflow"**

The workflow will:
- Build all packages
- Create the version tag automatically (if it doesn't exist)
- Create the GitHub Release

## Verify Your Release

After the workflow completes (takes 2-3 minutes):

1. Go to the **Releases** page on GitHub
2. You should see your new release with:
   - Release title: "CyberSec Terminal v2.0.0"
   - All artifacts attached:
     - `cybersec-terminal-v2.0.0.tar.gz` (Linux/macOS)
     - `cybersec-terminal-v2.0.0.zip` (Windows)
     - `cybersec_terminal-2.0.0-py3-none-any.whl` (Python wheel)
     - `cybersec_terminal-2.0.0.tar.gz` (Python source)
     - SHA-256 checksum files for each artifact

## Publish to PyPI (Optional)

To enable PyPI publishing:

1. **Get a PyPI API token:**
   - Go to https://pypi.org/manage/account/token/
   - Create a new API token
   - Copy the token (starts with `pypi-`)

2. **Add the token to GitHub Secrets:**
   - Go to your repository Settings
   - Navigate to Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `PYPI_API_TOKEN`
   - Value: Your API token
   - Click "Add secret"

3. **Publish a release:**
   - The `publish-pypi.yml` workflow runs automatically when you publish a GitHub Release
   - Or manually trigger it from the Actions tab

## Monitoring Workflow Runs

1. Go to the **Actions** tab
2. Select the workflow run you want to check
3. Click on the job name to see detailed logs
4. If there are any issues, the logs will show what went wrong

## Troubleshooting

### Tag already exists
```bash
# Delete the tag locally and remotely
git tag -d v2.0.0
git push --delete origin v2.0.0

# Then create it again
git tag -a v2.0.0 -m "Release v2.0.0"
git push origin v2.0.0
```

### Workflow didn't trigger
- Check that the tag starts with `v` (e.g., `v2.0.0`, not `2.0.0`)
- Verify the workflow file is on the default branch
- Check the Actions tab for any workflow runs

### Release artifacts are missing
- Check the workflow logs in the Actions tab
- Ensure the build step completed successfully
- Verify the version number matches across setup.py and the tag

## Next Steps

After creating a successful release:

1. **Update README.md** with the new release information
2. **Announce the release** to your users
3. **Monitor issues** for any bugs or feedback
4. **Plan the next version** based on user needs

## CI Workflow

The CI workflow (`ci.yml`) runs automatically on:
- Pull requests to main
- Pushes to main branch

It tests the build across:
- Multiple platforms (Ubuntu, Windows, macOS)
- Python versions 3.7 through 3.12

No action needed - it runs automatically to validate your changes!

## Need Help?

See the detailed documentation in `.github/workflows/README.md` for more information about each workflow.
