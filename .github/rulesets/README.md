# Repository rulesets

Version-controlled [repository ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets) definitions for MCP-Audit/MCTS.

Apply or refresh rulesets (repo admin, `gh` CLI authenticated):

```bash
./scripts/enable-branch-protection.sh MCP-Audit/MCTS
./scripts/enable-branch-protection.sh MCP-Audit/MCTS --dry-run   # preview only
```

If you previously applied a ruleset named `Protect main`, delete it under **Settings → Rules** after applying — this repo now uses `Protect release branches` (same file: `main.json`).

## Branch access model

| Branch | Who can update | How changes land |
|--------|----------------|------------------|
| `main` (current release) | **Maintainers** (`maintain` role) and **Admins** | PRs from `develop` or feature branches; maintainers merge when CI is green |
| `main_*` (pinned releases, e.g. `main_0.1.2`) | **Maintainers** and **Admins** | Same policy as `main` — hotfix PRs merged by maintainers |
| `develop` (integration) | **Admins only** (`admin` role) | Direct pushes by admins; contributors open PRs to `develop` from feature branches |

The `update` rule blocks direct pushes unless the actor is in `bypass_actors`. Repository role IDs (GitHub API):

| Role | `actor_id` | Typical members |
|------|------------|-----------------|
| `maintain` | `2` | Release maintainers — can merge PRs into `main` |
| `write` | `4` | Contributors — feature branches and PRs only |
| `admin` | `5` | Repo admins — full access including `develop` |

Assign roles under **Settings → Collaborators and teams**. Contributors should have **Write**; release maintainers **Maintain**; integration owners **Admin**.

`OrganizationAdmin` is included as an emergency bypass for org owners (not used on personal forks).

## Rulesets

| File | Branches | Rules summary |
|------|----------|---------------|
| `main.json` | `main` + `main_*` | Update restricted to bypass actors; PR + CI required; no force-push or deletion |
| `develop.json` | `develop` | Update restricted to admins; CI required; no force-push or deletion |

### `main` bypass actors

| Actor | Mode | Effect |
|-------|------|--------|
| `RepositoryRole` maintain (`2`) | `pull_request` | Can merge PRs into `main` when checks pass |
| `RepositoryRole` admin (`5`) | `always` | Full bypass for hotfixes / break-glass |
| `OrganizationAdmin` | `always` | Org-owner bypass |

### `develop` bypass actors

| Actor | Mode | Effect |
|-------|------|--------|
| `RepositoryRole` admin (`5`) | `always` | Only admins can push to `develop` |
| `OrganizationAdmin` | `always` | Org-owner bypass |

> **Note:** Admins with `bypass_mode: always` can push even when a status check is pending or failed. Run CI before pushing to `develop`, or merge via PR from a branch so checks gate the commit.

## Required status checks

Both rulesets require these checks from [`.github/workflows/ci.yml`](../workflows/ci.yml):

| Check | Workflow job | What it covers |
|-------|--------------|----------------|
| `test` | `test` → `test-gate.yml` | Ruff, pytest, regression harness, wheel smoke, SARIF |
| `scoring-v2` | `scoring-v2` → `scoring-v2.yml` | v2 scoring tests + Spearman ρ ≥ 0.80 calibration gate |

`main` uses `strict_required_status_checks_policy: true` so PR branches must be up to date before merge.

## Changing access or checks

1. Edit `bypass_actors` or `rules` in the JSON file.
2. Re-run `enable-branch-protection.sh`.
3. Update [CONTRIBUTING.md](../../CONTRIBUTING.md) and this README.

If GitHub reports a missing check context, open a recent PR → **Checks** tab and copy the exact status names into `required_status_checks`.
