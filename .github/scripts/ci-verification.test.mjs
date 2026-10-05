import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { parseVerificationProfile } from '../../profiles/verification-profile.mjs';
import {
  VerificationError,
  parseVerificationArtifact,
  validateVerificationManifest,
  verifyCentralWorkflowRun,
} from './ci-verification.mjs';

const profile = parseVerificationProfile(JSON.parse(await readFile(
  fileURLToPath(new URL('../../profiles/weixin-ci-verification.json', import.meta.url)), 'utf8',
)));
const verifierSha = 'a'.repeat(40);
const expected = {
  repository: profile.repository,
  event: 'pull_request',
  pullRequestNumber: 4,
  baseSha: 'b'.repeat(40),
  headSha: 'c'.repeat(40),
  candidateSha: 'd'.repeat(40),
  queueParentSha: null,
  runId: '500',
  attempt: 2,
  checkSuiteId: '700',
  verifierRepository: 'li2233-max/pr-security-gate',
  verifierPath: '.github/workflows/independent-ci-verification.yml',
  verifierSha,
  callerPath: '.github/workflows/independent-ci-verification.yml',
  profile,
};

function manifestFor(overrides = {}) {
  return {
    schemaVersion: 1,
    repository: expected.repository,
    event: expected.event,
    pullRequestNumber: expected.pullRequestNumber,
    queueRef: expected.queueRef ?? null,
    baseSha: expected.baseSha,
    headSha: expected.headSha,
    candidateSha: expected.candidateSha,
    queueParentSha: expected.queueParentSha,
    verifier: {
      repository: expected.verifierRepository,
      path: expected.verifierPath,
      sha: expected.verifierSha,
    },
    profile: { id: expected.profile.profileId, sha256: expected.profile.profileDigest },
    run: { id: expected.runId, attempt: expected.attempt, checkSuiteId: expected.checkSuiteId },
    checks: profile.checks.map(check => ({
      id: check.id,
      status: 'passed',
      count: check.minimumCount,
      summary: 'passed',
    })),
    ...overrides,
  };
}

function provenanceFor(overrides = {}) {
  const run = {
    id: 500,
    run_attempt: 2,
    check_suite_id: 700,
    event: 'pull_request',
    head_sha: expected.headSha,
    path: expected.callerPath,
    status: 'completed',
    conclusion: 'success',
    pull_requests: [{ number: 4, base: { sha: expected.baseSha }, head: { sha: expected.headSha } }],
    referenced_workflows: [{ path: `${expected.verifierRepository}/${expected.verifierPath}@${verifierSha}`, sha: verifierSha }],
    ...overrides.run,
  };
  const jobs = [
    ...profile.checks.map((check, index) => ({ id: index + 1, run_id: 500, run_attempt: 2, name: check.id, conclusion: 'success', status: 'completed' })),
    { id: 99, run_id: 500, run_attempt: 2, name: 'publish-verification-manifest', conclusion: 'success', status: 'completed' },
  ];
  const checkRuns = profile.checks.map((check, index) => ({ id: 900 + index, name: check.id, status: 'completed', conclusion: 'success', head_sha: expected.candidateSha, check_suite: { id: 700 }, app: { slug: 'github-actions' } }));
  return { run, jobs: overrides.jobs ?? jobs, checkRuns: overrides.checkRuns ?? checkRuns };
}

function zipFor(name, content) {
  const fileName = Buffer.from(name, 'utf8');
  const bytes = Buffer.from(content, 'utf8');
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  crc = (crc ^ 0xffffffff) >>> 0;
  const local = Buffer.alloc(30 + fileName.length + bytes.length);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0x0800, 6);
  local.writeUInt16LE(0, 8);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(bytes.length, 18);
  local.writeUInt32LE(bytes.length, 22);
  local.writeUInt16LE(fileName.length, 26);
  fileName.copy(local, 30);
  bytes.copy(local, 30 + fileName.length);
  const central = Buffer.alloc(46 + fileName.length);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(0x0314, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0x0800, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(bytes.length, 20);
  central.writeUInt32LE(bytes.length, 24);
  central.writeUInt16LE(fileName.length, 28);
  fileName.copy(central, 46);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(central.length, 12);
  eocd.writeUInt32LE(local.length, 16);
  return Buffer.concat([local, central, eocd]);
}

test('accepts an exhaustive manifest bound to current PR and run tuple', () => {
  const validated = validateVerificationManifest(manifestFor(), expected);
  assert.equal(validated.length, profile.checks.length);
  assert.ok(validated.every(item => item.status === 'passed'));
});

test('rejects stale candidate/base/head, run id, attempt, profile, or verifier SHA', () => {
  for (const field of ['baseSha', 'headSha', 'candidateSha']) {
    assert.throws(() => validateVerificationManifest(manifestFor({ [field]: 'e'.repeat(40) }), expected), VerificationError, field);
  }
  for (const [key, value] of Object.entries({ id: '501', attempt: 1, checkSuiteId: '701' })) {
    assert.throws(() => validateVerificationManifest(manifestFor({ run: { ...manifestFor().run, [key === 'id' ? 'id' : key]: value } }), expected), VerificationError, key);
  }
  assert.throws(() => validateVerificationManifest(manifestFor({ profile: { id: 'other', sha256: 'f'.repeat(64) } }), expected), VerificationError, 'profile');
  assert.throws(() => validateVerificationManifest(manifestFor({ verifier: { ...manifestFor().verifier, sha: 'e'.repeat(40) } }), expected), VerificationError, 'verifier');
});

test('rejects missing, duplicate, unknown, failed, skipped, under-count and forged result fields', () => {
  const good = manifestFor();
  assert.throws(() => validateVerificationManifest({ ...good, checks: good.checks.slice(1) }, expected), /check inventory/);
  assert.throws(() => validateVerificationManifest({ ...good, checks: [...good.checks, good.checks[0]] }, expected), /duplicate/);
  assert.throws(() => validateVerificationManifest({ ...good, checks: [...good.checks.slice(1), { ...good.checks[0], id: 'other' }] }, expected), /unknown check/);
  for (const status of ['failed', 'skipped', 'neutral']) {
    assert.throws(() => validateVerificationManifest({ ...good, checks: good.checks.map((item, index) => index ? item : { ...item, status }) }, expected), /must pass/);
  }
  assert.throws(() => validateVerificationManifest({ ...good, checks: good.checks.map((item, index) => index ? item : { ...item, count: 0 }) }, expected), /minimum/);
  assert.throws(() => validateVerificationManifest({ ...good, extraClaim: true }, expected), /unknown/);
});

test('rejects oversized manifests and malformed JSON inputs', () => {
  assert.throws(() => validateVerificationManifest(' '.repeat(65_537), expected), /size/);
  assert.throws(() => validateVerificationManifest('{not-json', expected), /JSON/);
});

test('accepts only the approved reusable run with exact caller and nested verifier provenance', () => {
  const { run, jobs, checkRuns } = provenanceFor();
  const callerTemplate = 'name: independent-ci-verification\nuses: li2233-max/pr-security-gate/.github/workflows/independent-ci-verification.yml@{{VERIFIER_SHA}}\n';
  const callerText = callerTemplate.replace('{{VERIFIER_SHA}}', verifierSha);
  const result = verifyCentralWorkflowRun(run, jobs, checkRuns, manifestFor(), {
    ...expected,
    callerTemplate,
    callerWorkflowText: callerText,
  });
  assert.equal(result.length, profile.checks.length);
  assert.equal(verifyCentralWorkflowRun(run, jobs, [...checkRuns, { ...checkRuns[0], check_suite: { id: 800 } }], manifestFor(), {
    ...expected,
    callerTemplate,
    callerWorkflowText: callerText,
  }).length, profile.checks.length);
  assert.equal(verifyCentralWorkflowRun(run, jobs, checkRuns.map(check => ({ ...check, head_sha: expected.headSha })), manifestFor(), {
    ...expected,
    callerTemplate,
    callerWorkflowText: callerText,
  }).length, profile.checks.length);
});

test('rejects wrong workflow path, unapproved nested workflow SHA, stale run/check suite, or modified caller', () => {
  const valid = provenanceFor();
  const checkArgs = manifest => ({ ...expected, callerTemplate: 'fixed caller', callerWorkflowText: 'fixed caller', manifest });
  assert.throws(() => verifyCentralWorkflowRun({ ...valid.run, path: '.github/workflows/quality.yml' }, valid.jobs, valid.checkRuns, manifestFor(), checkArgs()), /caller workflow/);
  assert.throws(() => verifyCentralWorkflowRun({ ...valid.run, referenced_workflows: [{ ...valid.run.referenced_workflows[0], sha: 'e'.repeat(40) }] }, valid.jobs, valid.checkRuns, manifestFor(), checkArgs()), /nested workflow/);
  assert.throws(() => verifyCentralWorkflowRun({ ...valid.run, run_attempt: 1 }, valid.jobs, valid.checkRuns, manifestFor(), checkArgs()), /attempt/);
  assert.throws(() => verifyCentralWorkflowRun(valid.run, valid.jobs, [{ ...valid.checkRuns[0], check_suite: { id: 701 } }], manifestFor(), checkArgs()), /check-run inventory/);
  assert.throws(() => verifyCentralWorkflowRun(valid.run, valid.jobs, valid.checkRuns, manifestFor(), { ...checkArgs(), callerWorkflowText: 'modified caller' }), /caller workflow/);
});

test('rejects duplicate, unknown, missing, skipped or failed GitHub jobs', () => {
  const valid = provenanceFor();
  const args = { ...expected, callerTemplate: 'fixed caller', callerWorkflowText: 'fixed caller' };
  assert.throws(() => verifyCentralWorkflowRun(valid.run, valid.jobs.slice(1), valid.checkRuns, manifestFor(), args), /job inventory/);
  assert.throws(() => verifyCentralWorkflowRun(valid.run, [...valid.jobs, valid.jobs[0]], valid.checkRuns, manifestFor(), args), /duplicate job/);
  assert.throws(() => verifyCentralWorkflowRun(valid.run, [...valid.jobs.slice(1), { name: 'made-up', status: 'completed', conclusion: 'success' }], valid.checkRuns, manifestFor(), args), /unknown job/);
  assert.throws(() => verifyCentralWorkflowRun(valid.run, valid.jobs.map((job, index) => index ? job : { ...job, conclusion: 'skipped' }), valid.checkRuns, manifestFor(), args), /job.*success/i);
  assert.throws(() => verifyCentralWorkflowRun(valid.run, valid.jobs.slice(0, -1), valid.checkRuns, manifestFor(), args), /job inventory/);
});

test('rejects unsafe archive members before accepting artifact bytes', () => {
  const json = JSON.stringify(manifestFor());
  const valid = zipFor('verification.json', json);
  assert.deepEqual(parseVerificationArtifact(valid), JSON.parse(json));
  for (const name of ['../verification.json', 'nested/verification.json', 'verification.json/../x']) {
    assert.throws(() => parseVerificationArtifact(zipFor(name, json)), /only verification.json/);
  }
  assert.throws(() => parseVerificationArtifact(Buffer.concat([valid, Buffer.from('extra')])), /trailing/);
  assert.throws(() => parseVerificationArtifact(Buffer.alloc(1_048_577)), /size/);
});
