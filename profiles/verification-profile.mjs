import { createHash } from 'node:crypto';

export class VerificationProfileError extends Error {}

const CHECK_EVIDENCE = Object.freeze({
  'secret-scan': 'secret_scan',
  'dependency-scan': 'dependency_scan',
  'production-hardening-tests': 'test',
});
const PROFILE_KEYS = ['schemaVersion', 'profileId', 'repository', 'events', 'checks', 'scanRoots', 'tools'];
const HEX_64 = /^[a-f0-9]{64}$/;
const POSIX_RELATIVE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.?($|\/))[A-Za-z0-9._/-]+$/;

function fail(message) {
  throw new VerificationProfileError(message);
}

function object(value, label, allowedKeys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const unknown = Object.keys(value).filter(key => !allowedKeys.includes(key));
  if (unknown.length) fail(`${label} contains unknown key ${unknown[0]}`);
  const missing = allowedKeys.filter(key => !Object.hasOwn(value, key));
  if (missing.length) fail(`${label} is missing ${missing[0]}`);
  return value;
}

function text(value, label) {
  if (typeof value !== 'string' || !value.trim() || value !== value.trim()) fail(`${label} must be non-empty text`);
  return value;
}

function path(value, label) {
  text(value, label);
  if (!POSIX_RELATIVE_PATH.test(value) || value.includes('\\') || value.includes('//')) fail(`${label} is an unsafe path`);
  return value;
}

function digest(value, label) {
  if (typeof value !== 'string' || !HEX_64.test(value)) fail(`${label} must be a 64-character SHA-256`);
  return value;
}

function imageDigest(value, label) {
  text(value, label);
  if (!/^[a-z0-9./-]+@sha256:[a-f0-9]{64}$/.test(value)) fail(`${label} must use an immutable image digest`);
  return value;
}

export function parseVerificationProfile(raw) {
  object(raw, 'profile', PROFILE_KEYS);
  if (raw.schemaVersion !== 1) fail('schemaVersion is unsupported');
  if (raw.profileId !== 'weixin-v1') fail('profileId is unsupported');

  object(raw.repository, 'repository', ['id', 'fullName']);
  if (raw.repository.id !== 1378303598 || raw.repository.fullName !== 'li2233-max/weixin') fail('repository identity is not approved');

  if (!Array.isArray(raw.events) || raw.events.length !== 2 || new Set(raw.events).size !== 2 ||
      !['pull_request', 'merge_group'].every(event => raw.events.includes(event))) {
    fail('event list must be exactly pull_request and merge_group');
  }

  if (!Array.isArray(raw.checks)) fail('checks must be an array');
  const seenChecks = new Set();
  for (const [index, check] of raw.checks.entries()) {
    object(check, `checks[${index}]`, ['id', 'evidenceType', 'minimumCount']);
    text(check.id, `checks[${index}].id`);
    if (!Object.hasOwn(CHECK_EVIDENCE, check.id)) fail(`unknown check ${check.id}`);
    if (seenChecks.has(check.id)) fail(`duplicate check ${check.id}`);
    seenChecks.add(check.id);
    if (check.evidenceType !== CHECK_EVIDENCE[check.id]) fail(`checks[${index}].evidenceType does not match the fixed mapping`);
    if (!Number.isSafeInteger(check.minimumCount) || check.minimumCount < 1) fail(`checks[${index}].minimumCount must be a positive integer`);
  }
  if (seenChecks.size !== Object.keys(CHECK_EVIDENCE).length || Object.keys(CHECK_EVIDENCE).some(id => !seenChecks.has(id))) {
    fail('required checks are missing');
  }

  if (!Array.isArray(raw.scanRoots) || raw.scanRoots.length === 0 || new Set(raw.scanRoots).size !== raw.scanRoots.length) fail('scanRoots must be non-empty and unique');
  for (const [index, root] of raw.scanRoots.entries()) path(root, `scanRoots[${index}]`);

  object(raw.tools, 'tools', ['gitleaks', 'nodeTest']);
  object(raw.tools.gitleaks, 'tools.gitleaks', ['version', 'platform', 'archiveSha256']);
  if (!/^\d+\.\d+\.\d+$/.test(text(raw.tools.gitleaks.version, 'tools.gitleaks.version'))) fail('tools.gitleaks.version must be an exact release');
  if (raw.tools.gitleaks.platform !== 'linux_x64') fail('tools.gitleaks.platform is unsupported');
  digest(raw.tools.gitleaks.archiveSha256, 'tools.gitleaks.archiveSha256');
  object(raw.tools.nodeTest, 'tools.nodeTest', ['image', 'version']);
  imageDigest(raw.tools.nodeTest.image, 'tools.nodeTest.image');
  if (!/^20\.\d+\.\d+$/.test(text(raw.tools.nodeTest.version, 'tools.nodeTest.version'))) fail('tools.nodeTest.version must be an exact Node 20 release');

  const profileDigest = createHash('sha256').update(JSON.stringify(raw)).digest('hex');
  return Object.freeze({ ...raw, profileDigest });
}
