# Instructions for Pushing v2.0.0 Tag

## Current Status

The annotated git tag `v2.0.0` has been successfully created locally with the message "Release v2.0.0" on commit `6e3d27e` (the current HEAD of branch `copilot/release-version-v2-0-0`).

However, the tag could not be pushed to the remote repository due to repository protection rules:

```
remote: error: GH013: Repository rule violations found for refs/tags/v2.0.0.
remote: - Cannot create ref due to creations being restricted.
```

## Required Action

To complete the release process, a repository administrator needs to push the tag manually. This can be done in one of the following ways:

### Option 1: Push the Tag Manually (Recommended)

If you have administrative access to the repository, you can push the tag directly:

```bash
# Fetch the latest branch
git fetch origin copilot/release-version-v2-0-0

# Checkout the branch
git checkout copilot/release-version-v2-0-0

# Create the annotated tag
git tag -a v2.0.0 -m "Release v2.0.0"

# Push the tag (requires admin privileges or rule bypass)
git push origin v2.0.0
```

### Option 2: Update Repository Rules

Temporarily adjust the repository rules to allow tag creation:
1. Go to https://github.com/morgang213/cs-pro/settings/rules
2. Find the rule preventing tag creation
3. Temporarily disable or modify the rule to allow tag creation
4. Push the tag using the command: `git push origin v2.0.0`
5. Re-enable the repository rule

### Option 3: Create Tag via GitHub Web Interface

1. Go to https://github.com/morgang213/cs-pro/releases/new
2. Click "Choose a tag"
3. Type `v2.0.0` and select "Create new tag: v2.0.0 on publish"
4. Set target to the branch `copilot/release-version-v2-0-0`
5. Fill in release title: "CyberSec Terminal v2.0.0"
6. Use the content from `RELEASE_NOTES_v2.0.0.md` for the description
7. Publish the release

Note: This will create the tag and trigger the deploy.yml workflow automatically.

## What Happens Next

Once the tag `v2.0.0` is pushed to the remote repository:

1. The GitHub Actions workflow `.github/workflows/deploy.yml` will be triggered automatically
2. The workflow will:
   - Build release packages (tar.gz, zip, wheel)
   - Create a GitHub Release with the tag
   - Upload release artifacts
   - Optionally publish to PyPI (if configured)

## Current Tag Information

- **Tag name**: v2.0.0
- **Tag message**: "Release v2.0.0"
- **Target commit**: 6e3d27e6d85de236db166f37d3715ea2cb9fdd2f
- **Branch**: copilot/release-version-v2-0-0
- **Tagger**: copilot-swe-agent[bot]
- **Date**: Mon Jan 12 17:05:20 2026 +0000

## Verification

After pushing the tag, you can verify it with:

```bash
git ls-remote --tags origin | grep v2.0.0
```

Or view it on GitHub at:
https://github.com/morgang213/cs-pro/releases/tag/v2.0.0
