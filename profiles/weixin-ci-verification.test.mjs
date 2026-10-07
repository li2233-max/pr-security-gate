import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { parseVerificationProfile, VerificationProfileError } from './verification-profile.mjs';

const profilePath = fileURLToPath(new URL('./weixin-ci-verification.json', import.meta.url));
const profile = JSON.parse(await readFile(profilePath, 'utf8'));

test('accepts the centrally pinned weixin verification profile', () => {
  const parsed = parseVerificationProfile(profile);
  assert.equal(parsed.repository.id, 1378303598);
  assert.deepEqual(parsed.events, ['pull_request', 'merge_group']);
  assert.deepEqual(parsed.checks.map(({ id }) => id), [
    'secret-scan',
    'dependency-scan',
    'production-hardening-tests',
  ]);
  assert.equal(Object.hasOwn(parsed, 'trustedTests'), false);
  assert.deepEqual(Object.keys(parsed.tools).sort(), ['gitleaks', 'nodeTest']);
});

test('retains the pinned Node image required by dependency audit', () => {
  assert.match(profile.tools.nodeTest.image, /^node@sha256:[a-f0-9]{64}$/);
});

test('approves only the published immutable verifier release for weixin', async () => {
  const approved = JSON.parse(await readFile(new URL('./approved-verifiers.json', import.meta.url), 'utf8'));
  assert.equal(approved.verifiers['weixin-v1'].sha, '7e696f1668fcf0a5c928d6863cae9a2e7209da84');
});

test('rejects unknown keys and unsupported schema versions', () => {
  assert.throws(() => parseVerificationProfile({ ...profile, callerOverride: true }), VerificationProfileError);
  assert.throws(() => parseVerificationProfile({ ...profile, schemaVersion: 2 }), /schemaVersion/);
});

test('rejects an incomplete or duplicate required check inventory', () => {
  assert.throws(() => parseVerificationProfile({ ...profile, checks: profile.checks.slice(1) }), /required checks/);
  assert.throws(() => parseVerificationProfile({ ...profile, checks: [...profile.checks, profile.checks[0]] }), /duplicate/);
  assert.throws(() => parseVerificationProfile({ ...profile, checks: [...profile.checks, { id: 'sast-config-scan', evidenceType: 'static_analysis', minimumCount: 1 }] }), /unknown check/);
  assert.throws(() => parseVerificationProfile({ ...profile, checks: [...profile.checks, { id: 'made-up-check', evidenceType: 'authorization_test', minimumCount: 1 }] }), /unknown check/);
  const obsoletePathMapping = structuredClone(profile);
  obsoletePathMapping.checks[0].evidencePaths = [];
  assert.throws(() => parseVerificationProfile(obsoletePathMapping), /unknown key/);
});

test('rejects unpinned retained tool references', () => {
  const unpinnedTool = structuredClone(profile);
  unpinnedTool.tools.nodeTest.image = 'node:20';
  assert.throws(() => parseVerificationProfile(unpinnedTool), /immutable image digest/);

  const unpinnedGitleaks = structuredClone(profile);
  unpinnedGitleaks.tools.gitleaks.version = 'latest';
  assert.throws(() => parseVerificationProfile(unpinnedGitleaks), /exact release/);
});

test('rejects unsupported events and unsafe scan paths', () => {
  assert.throws(() => parseVerificationProfile({ ...profile, events: ['workflow_dispatch'] }), /event/);
  const unsafePath = structuredClone(profile);
  unsafePath.scanRoots.push('../outside');
  assert.throws(() => parseVerificationProfile(unsafePath), /path/);
});
