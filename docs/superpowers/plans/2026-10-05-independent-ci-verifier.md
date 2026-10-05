# Independent CI Verifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a central, immutable, isolated CI verifier whose successful checks the PR gate can attribute to an approved verifier SHA and the current PR or merge-queue candidate.

**Architecture:** Add a `workflow_call` reusable verifier in `pr-security-gate`, a project profile that pins trusted checks and test inputs, and read-only provenance validation in the existing gate. The verifier emits only fixed named GitHub checks and a bounded result manifest from trusted workflow code; candidate files are data, and code tests run without GitHub tokens or network. Preserve the present blanket rejection of ordinary workflow checks.

**Tech Stack:** GitHub Actions reusable workflows, Node.js 20 built-ins, GitHub Actions REST API, Semgrep/Gitleaks fixed release artifacts, Docker on GitHub-hosted Ubuntu, `node:test`.

**Spec:** `docs/superpowers/specs/2026-09-28-independent-ci-verification-design.md`

## Global Constraints

- Pin every trusted workflow, action, scanner, ruleset and container image to an audited immutable revision or digest.
- No business secrets, write permissions, persistent credentials, Docker socket, Actions runtime credentials or network inside candidate-code tests.
- Ordinary checks from a PR that modifies `.github/workflows/` or `.github/actions/` remain untrusted.
- Bind every result to repository ID, event, base SHA, head SHA, merge candidate SHA, run ID and run attempt; any mismatch is unavailable and BLOCK.
- Never download or execute arbitrary candidate artifacts; only accept the single schema-validated bounded result manifest emitted by the verifier.
- Keep private `weixin` tests in `weixin`; register approved base/test commit and file digests rather than copying private source into the public central repository.
- Preserve the current fail-closed behavior for model, architecture, debt, required evidence and snapshot errors.
- Never merge a PR or create/move a release tag until ordinary protected checks pass and the user confirms the exact landing SHA.

## Review Focus

- A pull request cannot change the independent entry, verifier version, permissions, profile, scanner rules or trusted test fixture used to verify itself.
- A stale PR merge SHA, stale base, changed head or changed merge-queue parent cannot reuse a successful run or manifest.
- Candidate tests cannot access `GITHUB_TOKEN`, secrets, runner mounts, runtime commands, credentials or network, and cannot forge a passing manifest.
- Missing test files, skipped jobs, empty scan targets, scanner parse errors and truncated manifests all remain failures.
- Private baseline test contents never enter the public `pr-security-gate` repository or public artifacts.

---

### Task 1: Define the immutable project verifier profile

**Files:**
- Create: `profiles/weixin-ci-verification.json`
- Create: `profiles/weixin-ci-verification.test.mjs`
- Modify: `package.json`

**Interfaces:**
- Profile schema v1 lists repository ID/name, supported events, exact check IDs, immutable tool/container/ruleset references, scan roots, and per-check minimum target/test counts.
- Private test sources are identified by approved repository commit, exact paths, and SHA-256 digests; no private contents are stored centrally.

- [ ] Write tests rejecting unpinned tool references, duplicate/unknown check IDs, unsafe paths, missing required checks, unsupported events and missing private-source digests.
- [ ] Run `node --test profiles/weixin-ci-verification.test.mjs`; confirm failure before adding the schema/parser.
- [ ] Implement a strict profile parser that rejects unknown keys and fails closed on unsupported schema versions.
- [ ] Run the profile tests; confirm pass.
- [ ] Register profile tests in `npm test` and run the full suite.
- [ ] Commit the independently reviewable profile/schema change.

### Task 2: Implement bounded manifest and provenance validation

**Files:**
- Create: `.github/scripts/ci-verification.mjs`
- Create: `.github/scripts/ci-verification.test.mjs`
- Modify: `.github/scripts/pr-ai-review.mjs`
- Modify: `.github/scripts/pr-ai-review.test.mjs`

**Interfaces:**
- `validateVerificationManifest(input, expected)` validates schema, size, exact repository/event/SHA/run/attempt/check identities, approved profile digest and exhaustive result set; it returns normalized evidence or a typed unavailable reason.
- `verifyCentralWorkflowRun(run, jobs, checkRuns, artifact, expected, policy)` validates workflow path/repository/SHA, GitHub `referenced_workflows`, event, suite/run/attempt, exact required jobs and current candidate before invoking the manifest validator.
- Existing evidence collection adds `github-actions-central-verifier` only for these validated checks; regular workflow checks continue through the existing unchanged-base guard.

- [ ] Write adversarial tests for stale SHA/base, unapproved/missing nested workflow SHA, wrong run/attempt, caller workflow edits, duplicate/unknown jobs, missing/skipped checks, oversized manifest, unsafe archive entries, extra manifest fields and forged evidence claims.
- [ ] Run targeted tests and verify they fail before implementation.
- [ ] Implement pure validation functions with injected GitHub API inputs; do not mutate repository state or trust manifest self-asserted provenance.
- [ ] Add API lookup to discover the verifier workflow run from check-run details, validate its GitHub run/check-suite/job metadata, and download only the exact run/attempt manifest after provenance succeeds.
- [ ] Require the current manifest tuple to equal the gate's existing base/head/candidate snapshot and the merge-queue parent when applicable.
- [ ] Re-check PR/queue freshness after evidence collection; map only the fixed profile check IDs to policy evidence types.
- [ ] Ensure trusted central evidence cannot override scanner failures, security findings, architecture or debt BLOCK.
- [ ] Run targeted tests; then run the entire `npm test` suite.
- [ ] Commit the evidence/provenance change.

### Task 3: Add the reusable isolated verifier workflow

**Files:**
- Create: `.github/workflows/independent-ci-verification.yml`
- Create: `templates/project-independent-ci-verification.yml`
- Modify: `tests/reusable-workflow.test.mjs`
- Modify: `docs/pr-ai-review-setup.md`
- Modify: `README.md`

**Interfaces:**
- Caller workflow is a canonical `pull_request` plus `merge_group` wrapper with minimum read-only token permissions, no steps, no inputs and no secrets.
- Verifier workflow accepts no caller-selected commands, scanner config, test paths, refs or artifact names; it resolves candidate identities from the GitHub event/API and uses the approved project profile.
- A single publisher creates `verification.json` with exhaustive exact check IDs and bounded sanitized summaries only after all required jobs succeed.

- [ ] Write workflow contract tests for exact caller template, triggers, SHA-pinned `uses`, required token permissions, absent secrets/steps, and exact verifier job/check names.
- [ ] Run targeted tests and confirm failure before writing workflow/template docs.
- [ ] Implement read-only candidate/base checkout and snapshot validation using either reviewed actions pinned to full commit SHA or a token-safe `git` fetch whose token never reaches test/scanner processes.
- [ ] Implement static scans and production-hardening validation from central verifier code and central rules; parse candidate workflow/config files only as data.
- [ ] Implement central private-test checkout at the approved test commit/digests and run those tests against candidate implementation inside a disposable, non-root, read-only, no-network container with no token, secrets, runtime command files, caches or host mounts.
- [ ] Implement pinned dependency audit without executing project install scripts or candidate commands.
- [ ] Publish a single size-limited schema-v1 manifest bound to the run and attempt; sanitize/truncate candidate-originated text and do not emit workflow commands from it.
- [ ] Run workflow/template tests and the full `npm test` suite.
- [ ] Commit workflow, template and documentation.

### Task 4: Add real GitHub validation and prepare the release PR

**Files:**
- Modify: `.github/workflows/test.yml` only if needed for a trusted caller fixture.
- Modify: `docs/pr-ai-review-setup.md` if real findings require contract clarification.
- No changes: `miniprogram` or private repository workflow in this center PR.

**Interfaces:**
- Central test workflow produces a startup-successful run; all third-party actions are permitted or avoided according to actual repository Actions policy.
- Release PR records exact verifier candidate SHA and a proposed immutable G->V profile pin; no floating tags or partial SHAs.

- [ ] Run `git diff --check`, profile/workflow unit tests and `npm test`; record complete counts.
- [ ] Run or rerun the central GitHub test workflow and inspect startup, job results, and provenance on the public Actions page.
- [ ] Open/update the central PR from the authorized branch; document all fixed SHAs, permissions and threat-model limitations.
- [ ] Confirm merge SHA and approval requirements from GitHub. Do not merge or tag without explicit confirmation for that exact SHA.
- [ ] After authorized merge, create the immutable verifier release reference only if the validated branch protection and CI are active; verify the published tag resolves to the approved full SHA.
- [ ] Wire the newly released verifier SHA into the central gate in a follow-up commit/release and create a minimal `weixin` integration change only after that release exists.

## End-to-end acceptance

- On a `weixin` PR that modifies `quality.yml`, ordinary checks remain listed as untrusted while the independent verifier passes on that candidate SHA.
- The gate consumes the verifier checks as trusted only when its immutable V/G references, canonical caller workflow, run metadata, check suite, artifact, manifest and all snapshot SHAs match.
- A test mutation or scanner suppression cannot replace the approved private base tests or center rules.
- Re-run, stale base/head/merge SHA, malformed/missing artifact, skipped test, API 403/404, workflow tamper or disallowed action produces unavailable/BLOCK with a bounded redacted diagnostic.
- Real check evidence on the current candidate supplies payment/refund and applicable static/secret evidence. Remaining P2/debt and any independent architecture/security findings remain separately visible and can still BLOCK.
- Existing 79 tests and all new tests pass, and the GitHub-hosted workflow starts and completes successfully.
