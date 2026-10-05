import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { evidenceTypeForCheck, parseVerificationProfile, VerificationProfileError } from './verification-profile.mjs';

const profilePath = fileURLToPath(new URL('./weixin-ci-verification.json', import.meta.url));
const profile = JSON.parse(await readFile(profilePath, 'utf8'));

test('accepts the centrally pinned weixin verification profile', () => {
  const parsed = parseVerificationProfile(profile);
  assert.equal(parsed.repository.id, 1378303598);
  assert.deepEqual(parsed.events, ['pull_request', 'merge_group']);
  assert.deepEqual(parsed.checks.map(({ id }) => id), [
    'secret-scan',
    'sast-config-scan',
    'dependency-scan',
    'payment-refund-tests',
    'authorization-tests',
    'production-hardening-tests',
  ]);
  assert.equal(parsed.trustedTests.length, 2);
});

test('pins the exact valid Semgrep ruleset bytes in the verification profile', async () => {
  const rules = await readFile(new URL('./weixin-semgrep-rules.yml', import.meta.url), 'utf8');
  const canonicalRules = Buffer.from(rules.replace(/\r\n/g, '\n'), 'utf8');
  assert.equal(profile.tools.semgrep.rulesetSha256, createHash('sha256').update(canonicalRules).digest('hex'));
});

test('rejects unknown keys and unsupported schema versions', () => {
  assert.throws(() => parseVerificationProfile({ ...profile, callerOverride: true }), VerificationProfileError);
  assert.throws(() => parseVerificationProfile({ ...profile, schemaVersion: 2 }), /schemaVersion/);
});

test('rejects an incomplete or duplicate required check inventory', () => {
  assert.throws(() => parseVerificationProfile({ ...profile, checks: profile.checks.slice(1) }), /required checks/);
  assert.throws(() => parseVerificationProfile({ ...profile, checks: [...profile.checks, profile.checks[0]] }), /duplicate/);
  assert.throws(() => parseVerificationProfile({ ...profile, checks: [...profile.checks, { id: 'made-up-check', evidenceType: 'authorization_test', minimumCount: 1, evidencePaths: [] }] }), /unknown check/);
});

test('rejects unpinned tool and ruleset references', () => {
  const unpinnedTool = structuredClone(profile);
  unpinnedTool.tools.semgrep.version = 'latest';
  assert.throws(() => parseVerificationProfile(unpinnedTool), /exact release/);

  const unpinnedRules = structuredClone(profile);
  unpinnedRules.tools.semgrep.rulesetSha256 = 'mutable';
  assert.throws(() => parseVerificationProfile(unpinnedRules), /SHA-256/);
});

test('rejects unsupported events and unsafe scan paths', () => {
  assert.throws(() => parseVerificationProfile({ ...profile, events: ['workflow_dispatch'] }), /event/);
  const unsafePath = structuredClone(profile);
  unsafePath.scanRoots.push('../outside');
  assert.throws(() => parseVerificationProfile(unsafePath), /path/);
});

test('requires immutable private test source and per-file digests', () => {
  const missingCommit = structuredClone(profile);
  missingCommit.trustedTests[0].sourceCommit = 'main';
  assert.throws(() => parseVerificationProfile(missingCommit), /full commit SHA/);

  const missingDigest = structuredClone(profile);
  delete missingDigest.trustedTests[0].files[0].sha256;
  assert.throws(() => parseVerificationProfile(missingDigest), /missing sha256/);
});

test('maps trusted business tests only to the exact code paths covered by their pinned test sources', () => {
  const authorization = profile.checks.find(check => check.id === 'authorization-tests');
  const payment = profile.checks.find(check => check.id === 'payment-refund-tests');
  assert.equal(evidenceTypeForCheck(authorization, ['cloudbase/cloudfunctions/manageStaff/index.js']), 'test');
  assert.equal(evidenceTypeForCheck(authorization, ['cloudbase/cloudfunctions/createOrder/payment-test-access.js']), 'authorization_test');
  assert.equal(evidenceTypeForCheck(payment, ['cloudbase/cloudfunctions/manageStaff/index.js']), 'test');
  assert.equal(evidenceTypeForCheck(payment, ['cloudbase/cloudfunctions/refundCallback/refund-callback-core.js']), 'transaction_test');
});
