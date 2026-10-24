# Core PR #6 — Full Test Environment Acceptance

**Status:** Review checklist, non-normative. This file does not approve or merge PR #6.
**Target PR:** https://github.com/vaidt/aura-poc-a-core-v3.3/pull/6
**Expected reviewed head:** `0e10964703c1e0273094b274d0969d422deab9f2` (re-read before use).

## Scope observed in the current report

One workflow change updates the CORE-001 full pytest environment to install the local project in editable mode with pytest, so declared project dependencies such as `rfc8785==0.1.4` are available. Any production-source or fixture change requires a separate review.

## Acceptance checklist

- [ ] Re-read PR state, exact head SHA, base SHA, changed-file list, and full workflow diff.
- [ ] Confirm only the intended workflow step changed.
- [ ] Verify installation uses the declared project metadata and does not bypass pinned dependency constraints.
- [ ] Confirm full pytest completes; collection success alone is insufficient.
- [ ] Confirm no required tests were skipped/marked xfail merely to obtain a green result.
- [ ] Confirm Docker/Compose, ARM64, x86_64, WASM, and cross-platform deterministic replay checks passed on the exact head.
- [ ] Inspect job logs to verify each required check actually executed, not merely that a wrapper job passed.
- [ ] Obtain independent review and confirm effective main protection before any merge decision.
- [ ] After any authorized merge, record merge SHA and new `main` SHA; rerun the full required suite on that SHA.
- [ ] Rebase/recreate dependent PRs from the updated base and rerun their own full suites.

## Fail-closed conditions

Do not promote if any mandatory job is skipped, only collection passed, the exact head lacks run evidence, the change expanded beyond the stated workflow scope, or review/protection requirements are unproven.

## Explicit non-effects

This CI environment fix does not establish protocol conformance, close DQ-006/CONF-003/C6, ratify P-008, establish M1/G1, or authorize release.
