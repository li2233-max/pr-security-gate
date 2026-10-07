# Remove Three PR Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove payment/refund tests, authorization tests, and Semgrep scanning from both repositories, delete the 16 weixin test files, and retire the two related architecture prerequisites without misrepresenting remaining checks.

**Architecture:** The central verifier becomes an exact three-check producer and consumer (secret, dependency, production hardening). Its new immutable verifier SHA is separately approved; a contract-only weixin baseline PR removes the old critical-path prerequisites before existing weixin PR #4 removes its three Quality jobs and the 16 test files.

**Tech Stack:** GitHub Actions YAML, Node.js 20 ESM and node:test, JSON policy/profile, Git/GitHub PRs.

**Spec:** `docs/superpowers/specs/2026-10-06-remove-three-ci-checks-design.md`

## 用户审阅摘要

中心仓库删除支付退款测试、授权测试和 Semgrep 三项独立检查，只保留密钥、依赖、生产配置检查；依赖审计仍要使用固定 Node 镜像。`weixin` 先用单独 PR 修改 `main` 架构契约，再在现有 PR #4 删除三个 Quality job 和全部 16 个对应测试文件，业务实现不删。中心版本需要先合并实现、再合并固定 SHA 批准；每个 PR 都等你审阅合并，不能把旧失败记录伪装成通过。

## Global Constraints

- Remove, do not skip or mark non-blocking, `payment-refund-tests`, `authorization-tests`, and `sast-config-scan` in both repositories.
- Delete only the 16 exact weixin test paths listed in the spec; do not delete payment, refund, role, or authorization application implementation.
- Retain central and weixin secret, dependency, and production-hardening checks; retain weixin architecture-owner-approval and the AI/architecture/debt gates.
- The weixin contract parser rejects empty `criticalPaths.requiredChecks`; delete the two obsolete entries in a separate contract-only PR, leaving other entries unchanged.
- Do not treat an absent check as passed, reuse an old candidate run, use mutable workflow refs, push directly to main, force-push, or merge without the user's per-PR confirmation.
- Check the actual GitHub Ruleset before claiming PR #4 is mergeable; repository-owner action may be needed to stop requiring deleted names.

## Review Focus

1. An old six-check profile or a removed check ID must be rejected by the new central profile parser (Task 1 test).
2. A manifest missing, skipping, or reporting zero for any retained check must still be rejected (Task 1 test).
3. A GitHub run containing an extra removed job under the new verifier must not count as the exact approved run (Task 1 test).
4. A stale candidate SHA or unapproved verifier SHA must not become trusted after the approval-registry update (Tasks 1 and 2 tests).
5. A candidate contract change must not waive requirements from protected main; baseline approval must come from the unchanged Quality workflow (Task 3 test and live PR check).

---

### Task 1: Publish a three-check central verifier

**Files:**
- Modify: `profiles/weixin-ci-verification.json`, `profiles/verification-profile.mjs`, `profiles/weixin-ci-verification.test.mjs`
- Modify: `.github/workflows/independent-ci-verification.yml`, `.github/scripts/independent-ci-check.mjs`
- Modify: `.github/scripts/ci-verification.test.mjs`, `tests/reusable-workflow.test.mjs`, `tests/independent-verification.test.mjs`
- Modify if active references remain: `.github/scripts/pr-ai-review.test.mjs`, `docs/independent-ci-verifier.md`, `references/evidence-requirements.md`
- Delete: `profiles/weixin-semgrep-rules.yml`
- Inspect, changing only if required by tests: `.github/scripts/ci-verification.mjs`, `.github/scripts/publish-verification-manifest.mjs`, `.github/scripts/pr-ai-review.mjs`

**Interfaces:**
- Consumes: fixed `weixin-v1` repository identity and existing verifier/manifest schema version 1.
- Produces: `parseVerificationProfile(raw)` accepts exactly `secret-scan`, `dependency-scan`, `production-hardening-tests`; the reusable workflow publishes a manifest containing exactly those IDs and their positive counts. Existing candidate/run/artifact provenance rules remain.

- [ ] **Step 1: Change the central regression expectations first.** In `profiles/weixin-ci-verification.test.mjs`, assert `parsed.checks.map(check => check.id)` deep-equals `['secret-scan', 'dependency-scan', 'production-hardening-tests']`, and `parseVerificationProfile` throws for an added old ID or missing retained ID. In `tests/reusable-workflow.test.mjs`, assert those three job headers plus `publish-verification-manifest` exist and the deleted job headers do not. In `.github/scripts/ci-verification.test.mjs`, assert an exact three-check manifest passes, while missing/zero retained results and an extra removed job throw `VerificationError`; retain stale SHA tests. Remove only Semgrep/trusted-test-specific tests and imports from `tests/independent-verification.test.mjs`; keep snapshot, safe diagnostic, and manifest provenance tests.
- [ ] **Step 2: Run the new tests before implementation.** Run `npm test` in the central repo. Expected: FAIL on six-check profile/workflow expectations; a failing test must identify the intended change, not an unrelated environment error.
- [ ] **Step 3: Remove the central producer paths.** Change the profile and `CHECK_EVIDENCE` mapping to the three exact checks. Remove `trustedTests`, Semgrep tool definition and rules file, `runSemgrep`, trusted-test download/install/run paths, and the three job branches. Keep `tools.nodeTest` and its pinned image because the retained dependency audit uses it; also keep Gitleaks scan roots, production hardening, common snapshot safety, and the pinned Gitleaks tool. In the workflow, remove the three jobs and their publisher `needs`/count env inputs; the profile-driven publisher still requires positive counts for the remaining jobs.
- [ ] **Step 4: Reconcile consumers and active documentation.** Keep manifest/run validation exhaustive against the new profile. Update any test or documentation that treats the removed checks as currently required; do not remove generic GitHub check provenance tests merely because their fixture uses an authorization check name. Keep the approval registry pinned to the old SHA until Task 2.
- [ ] **Step 5: Run the complete central tests.** Run `npm test`; expected: all tests pass. The CI-only container tests must also pass in the central PR, because local Windows skips them.
- [ ] **Step 6: Check the diff and residual references.** Run `git diff --check` and `rg -n 'sast-config-scan|payment-refund-tests|authorization-tests|trustedTests|weixin-semgrep-rules' .github profiles docs/independent-ci-verifier.md tests`. Expected: no active producer/profile requirement remains; negative tests and historical statements are reviewed individually.
- [ ] **Step 7: Commit and open the central PR.** Commit only central runtime, tests, and relevant docs as `fix(verifier): remove three independent checks`. Wait for user review/merge; record the actual merged implementation SHA as V rather than guessing it from the branch head.

### Task 2: Approve the new immutable central verifier

**Files:**
- Modify: `profiles/approved-verifiers.json`, `profiles/weixin-ci-verification.test.mjs`

**Interfaces:**
- Consumes: V, the actual 40-character commit SHA containing the merged Task 1 verifier workflow and profile.
- Produces: `approved-verifiers.json.verifiers['weixin-v1'].sha === V`; the later merged approval commit is G, used by the weixin AI review caller.

- [ ] **Step 1: Verify V.** Fetch central `main`; inspect V and confirm `.github/workflows/independent-ci-verification.yml` and the three-check profile are present at that exact SHA. Do not approve a mutable ref or an unmerged branch head.
- [ ] **Step 2: Change the pinned-SHA regression assertion first.** In `profiles/weixin-ci-verification.test.mjs`, make `approves only the published immutable verifier release for weixin` expect the exact V SHA.
- [ ] **Step 3: Verify the red test.** Run `npm test`; expected: FAIL because the registry still contains the old SHA.
- [ ] **Step 4: Update the registry.** Set only `verifiers['weixin-v1'].sha` to V in `profiles/approved-verifiers.json`.
- [ ] **Step 5: Verify the green tests and diff.** Run `npm test` and `git diff --check`; expected: PASS. Keep tests rejecting an unapproved or stale verifier SHA.
- [ ] **Step 6: Commit and publish.** Commit `fix(policy): approve three-check verifier`, open a separate central PR, and wait for user review/merge. Fetch central `main` afterward and record its actual approval commit SHA as G.

### Task 3: Establish the weixin architecture baseline on main

**Files:**
- Modify only: `.pr-security-gate/architecture.json` in a new weixin branch based on current `origin/main`.

**Interfaces:**
- Consumes: protected main architecture contract and existing unchanged `quality.yml` with `architecture-owner-approval`.
- Produces: a main contract whose `criticalPaths` no longer contain `payment-and-refund-integrity` or `buyer-and-verifier-access-control`; `production-configuration` and `architecture-policy` remain.

- [ ] **Step 1: Run the failing data assertion.** From the weixin repo, run the command below. Expected before edit: FAIL on the obsolete IDs.

```bash
node -e "const ids=require('./.pr-security-gate/architecture.json').criticalPaths.map(x=>x.id);if(['payment-and-refund-integrity','buyer-and-verifier-access-control'].some(x=>ids.includes(x))||!['production-configuration','architecture-policy'].every(x=>ids.includes(x)))process.exit(1)"
```
- [ ] **Step 2: Edit only the contract.** Remove the two complete critical-path objects; do not use empty `requiredChecks`, change the debt ledger, or edit `quality.yml` in this PR.
- [ ] **Step 3: Verify the contract data.** Re-run the Step 1 assertion; expected: PASS. Invoke central `validateArchitectureContract(raw)` on the edited file; expected: no exception. Run the existing central test `a contract change cannot approve its own relaxed rules`; expected: PASS.
- [ ] **Step 4: Check and commit the isolated diff.** Before committing, run `git diff --check` and `git diff --name-only origin/main`; expected: only `.pr-security-gate/architecture.json`. Commit `fix(policy): remove obsolete critical-path checks`; afterward `git diff --name-only origin/main...HEAD` must show the same single path.
- [ ] **Step 5: Open and validate the baseline PR.** Open a contract-only weixin PR; wait for its unchanged-workflow `architecture-owner-approval` plus AI/architecture review. The user reviews/merges this baseline before Task 4.

### Task 4: Update existing weixin PR #4

**Files:**
- Modify: `.github/workflows/quality.yml`, `.github/workflows/independent-ci-verification.yml`, `.github/workflows/pr-ai-review.yml` on `fix/gate-ci-baseline`.
- Delete: the exact 15 tracked `cloudbase/tests/*.test.js` files and `miniprogram/tests/payment-access-policy.test.js` listed in the spec; verify the list before editing.
- Modify only if active references break: current CI instructions or operational documentation; do not rewrite historical plans to pretend tests never existed.

**Interfaces:**
- Consumes: merged weixin baseline contract, approved V and G, and the existing PR #4 branch.
- Produces: PR #4 with no payment-refund-tests, authorization-tests, or sast-config-scan Quality jobs; no listed test files; independent caller pinned to V and AI review caller pinned to G; four retained weixin Quality jobs unchanged.

- [ ] **Step 1: Verify prerequisites.** Fetch both mains and confirm weixin main has the contract baseline and central G approves V. Enumerate `git ls-files cloudbase/tests miniprogram/tests`; expected: exactly the 16 spec paths and no additional target in those directories. Stop for user direction if the target set differs.
- [ ] **Step 2: Run the failing Quality assertion.** In `quality.yml`, assert job headers `payment-refund-tests`, `authorization-tests`, and `sast-config-scan` are absent, and `production-hardening-tests`, `dependency-scan`, `secret-scan`, and `architecture-owner-approval` remain. Expected before edit: FAIL on the three removed IDs.

```bash
node -e "const fs=require('fs');const s=fs.readFileSync('.github/workflows/quality.yml','utf8');const has=id=>new RegExp('^  '+id+':$','m').test(s);if(['payment-refund-tests','authorization-tests','sast-config-scan'].some(has)||!['production-hardening-tests','dependency-scan','secret-scan','architecture-owner-approval'].every(has))process.exit(1)"
```
- [ ] **Step 3: Remove only the requested files/jobs.** Delete the three job blocks from `quality.yml` and the exact 16 verified test files using reviewable file patches. Do not delete application implementation or four retained jobs.
- [ ] **Step 4: Update immutable callers and base.** Point the independent caller at V and the AI review caller at G. Merge current `origin/main` into the PR #4 branch without force-push.
- [ ] **Step 5: Verify locally.** Re-run the absence/presence assertions, `node miniprogram/scripts/validate-production-hardening.js`, JSON validation of `.pr-security-gate/architecture.json` and `.pr-security-gate/debt.json`, and `git diff --check`. Inspect changed-file list for unintended deletions. Do not claim payment/refund/authorization test or Semgrep coverage; it is gone.
- [ ] **Step 6: Commit and update PR #4.** Commit `ci: remove three Quality jobs and obsolete tests`, update existing PR #4, and wait for a fresh candidate SHA.
- [ ] **Step 7: Validate the live PR and Ruleset.** Inspect remaining Quality, independent verifier, AI security, and architecture results, plus the actual main Ruleset required-check list. If the Ruleset still requires deleted names, request the owner remove only those entries. If another legitimate gate blocks, report the reason and stop; do not synthesize success or merge automatically.

## Execution boundary

Tasks 1 and 2 require two distinct central merge decisions because G must approve the immutable merged V. Task 3 requires its own weixin baseline merge. Task 4 cannot truthfully be declared complete until those merges and a fresh PR #4 run occur. GitHub authentication may require the user to perform push/PR actions; local passing tests are not a substitute for live checks.
