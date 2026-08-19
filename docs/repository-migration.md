# Repository Migration Guide

This document describes how to complete the migration from four standalone scanner repositories to the unified **ICS OT Protector** monorepo.

## Current state

| Repository | Status | Monorepo path |
|------------|--------|---------------|
| `spinfosecurity/water-utility-protector` | Active (to be renamed) | `scanners/water/` |
| `spinfosecurity/Energy-Grid-Protector` | Pending archive | `scanners/energy-grid/` |
| `spinfosecurity/BAS-Guardian` | Pending archive | `scanners/bas/` |
| `spinfosecurity/Rail-OT-Protector` | Pending archive | `scanners/rail/` |

## Target state

- **One repo:** `spinfosecurity/ics-ot-protector`
- **Three archived repos** with README pointers to the monorepo
- **Automatic redirects** from `water-utility-protector` to `ics-ot-protector` (GitHub handles this after rename)

## One-command migration (org admin)

Requires [GitHub CLI](https://cli.github.com/) authenticated with admin access to the `spinfosecurity` organization:

```bash
chmod +x scripts/admin/archive-legacy-repos.sh
./scripts/admin/archive-legacy-repos.sh
```

This script:

1. Pushes an archive notice README to each legacy repo (from `docs/archive-notices/`)
2. Archives `Energy-Grid-Protector`, `BAS-Guardian`, and `Rail-OT-Protector`
3. Renames `water-utility-protector` → `ics-ot-protector`

To archive legacy repos without renaming the monorepo:

```bash
./scripts/admin/archive-legacy-repos.sh --skip-rename
```

## Manual steps

If you prefer to run each step yourself:

### 1. Push archive READMEs

Archive notice templates live in `docs/archive-notices/{energy-grid,bas,rail}/README.md`.

For each legacy repo, replace `README.md` on `main` with the corresponding notice and commit.

### 2. Archive legacy repositories

```bash
gh api -X PATCH repos/spinfosecurity/Energy-Grid-Protector -f archived=true
gh api -X PATCH repos/spinfosecurity/BAS-Guardian -f archived=true
gh api -X PATCH repos/spinfosecurity/Rail-OT-Protector -f archived=true
```

### 3. Rename the monorepo

```bash
gh repo rename ics-ot-protector --repo spinfosecurity/water-utility-protector -y
```

### 4. Update local clones

```bash
git remote set-url origin https://github.com/spinfosecurity/ics-ot-protector.git
```

## Archive notice content

Each archived repo README includes:

- A clear **archived** banner
- Link to `https://github.com/spinfosecurity/ics-ot-protector`
- Table mapping all four former repos to their monorepo paths
- Sector-specific quick-start commands
- Pointer to monorepo issues for bug reports and contributions

## FAQ

**Will old clone URLs break?**  
After renaming, GitHub redirects `water-utility-protector` URLs to `ics-ot-protector`. Update remotes when convenient.

**Can users still fork archived repos?**  
Archived repos remain readable but cannot receive new issues, PRs, or commits.

**Where do security advisories go?**  
Report vulnerabilities on the monorepo: https://github.com/spinfosecurity/ics-ot-protector/security/advisories/new
