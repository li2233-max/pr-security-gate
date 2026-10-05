import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';

const MAX_MANIFEST_BYTES = 65_536;
const MAX_ARCHIVE_BYTES = 1_048_576;
const SHA_40 = /^[a-f0-9]{40}$/;
const SHA_64 = /^[a-f0-9]{64}$/;

export class VerificationError extends Error {}

function reject(message) {
  throw new VerificationError(message);
}

function object(value, label, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject(`${label} must be an object`);
  const extras = Object.keys(value).filter(key => !keys.includes(key));
  if (extras.length) reject(`${label} contains unknown field ${extras[0]}`);
  const missing = keys.filter(key => !Object.hasOwn(value, key));
  if (missing.length) reject(`${label} is missing ${missing[0]}`);
  return value;
}

function exact(actual, expected, label) {
  if (actual !== expected) reject(`${label} does not match the current verification tuple`);
}

function isSha(value) {
  return typeof value === 'string' && SHA_40.test(value);
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function parseVerificationArtifact(input) {
  const archive = Buffer.isBuffer(input) ? input : Buffer.from(input ?? []);
  if (archive.length === 0 || archive.length > MAX_ARCHIVE_BYTES) reject('artifact archive size is invalid');
  const eocdFloor = Math.max(0, archive.length - 65_557);
  let eocd = -1;
  for (let offset = archive.length - 22; offset >= eocdFloor; offset -= 1) {
    if (archive.readUInt32LE(offset) === 0x06054b50) { eocd = offset; break; }
  }
  if (eocd < 0) reject('artifact is not a supported ZIP archive');
  const commentLength = archive.readUInt16LE(eocd + 20);
  if (eocd + 22 + commentLength !== archive.length) reject('artifact ZIP has trailing or truncated data');
  const disk = archive.readUInt16LE(eocd + 4);
  const centralDisk = archive.readUInt16LE(eocd + 6);
  const diskEntries = archive.readUInt16LE(eocd + 8);
  const totalEntries = archive.readUInt16LE(eocd + 10);
  const centralSize = archive.readUInt32LE(eocd + 12);
  const centralOffset = archive.readUInt32LE(eocd + 16);
  if (disk !== 0 || centralDisk !== 0 || diskEntries !== 1 || totalEntries !== 1 || centralOffset + centralSize !== eocd) {
    reject('artifact ZIP must contain exactly one non-ZIP64 entry on one disk');
  }
  if (centralOffset + 46 > eocd || archive.readUInt32LE(centralOffset) !== 0x02014b50) reject('artifact ZIP central directory is malformed');
  const flags = archive.readUInt16LE(centralOffset + 8);
  const method = archive.readUInt16LE(centralOffset + 10);
  const expectedCrc = archive.readUInt32LE(centralOffset + 16);
  const compressedSize = archive.readUInt32LE(centralOffset + 20);
  const uncompressedSize = archive.readUInt32LE(centralOffset + 24);
  const nameLength = archive.readUInt16LE(centralOffset + 28);
  const extraLength = archive.readUInt16LE(centralOffset + 30);
  const entryCommentLength = archive.readUInt16LE(centralOffset + 32);
  const startDisk = archive.readUInt16LE(centralOffset + 34);
  const externalAttributes = archive.readUInt32LE(centralOffset + 38);
  const localOffset = archive.readUInt32LE(centralOffset + 42);
  const entryEnd = centralOffset + 46 + nameLength + extraLength + entryCommentLength;
  if (entryEnd !== eocd || nameLength < 1 || startDisk !== 0) reject('artifact ZIP entry metadata is malformed');
  if ((flags & 1) !== 0 || ![0, 8].includes(method)) reject('artifact ZIP entry is encrypted or uses an unsupported compression method');
  if (uncompressedSize > MAX_MANIFEST_BYTES || compressedSize > MAX_ARCHIVE_BYTES) reject('artifact manifest size exceeds the limit');
  const unixMode = externalAttributes >>> 16;
  const fileType = unixMode & 0o170000;
  if (fileType !== 0 && fileType !== 0o100000) reject('artifact ZIP entry is not a regular file');
  const name = archive.subarray(centralOffset + 46, centralOffset + 46 + nameLength).toString('utf8');
  if (name !== 'verification.json') reject('artifact ZIP must contain only verification.json');
  if (localOffset + 30 > centralOffset || archive.readUInt32LE(localOffset) !== 0x04034b50) reject('artifact ZIP local header is malformed');
  const localFlags = archive.readUInt16LE(localOffset + 6);
  const localMethod = archive.readUInt16LE(localOffset + 8);
  const localNameLength = archive.readUInt16LE(localOffset + 26);
  const localExtraLength = archive.readUInt16LE(localOffset + 28);
  const localName = archive.subarray(localOffset + 30, localOffset + 30 + localNameLength).toString('utf8');
  if (localFlags !== flags || localMethod !== method || localName !== name) reject('artifact ZIP local and central headers disagree');
  if ((flags & 0x08) !== 0) reject('artifact ZIP data descriptors are not supported');
  const dataStart = localOffset + 30 + localNameLength + localExtraLength;
  const dataEnd = dataStart + compressedSize;
  if (dataEnd !== centralOffset) reject('artifact ZIP has hidden or overlapping data');
  let bytes;
  try {
    bytes = method === 0
      ? Buffer.from(archive.subarray(dataStart, dataEnd))
      : inflateRawSync(archive.subarray(dataStart, dataEnd), { maxOutputLength: MAX_MANIFEST_BYTES });
  } catch {
    reject('artifact ZIP manifest cannot be safely decompressed');
  }
  if (bytes.length !== uncompressedSize || crc32(bytes) !== expectedCrc) reject('artifact ZIP manifest integrity check failed');
  if (bytes.includes(0)) reject('artifact manifest must be UTF-8 JSON text');
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    reject('artifact manifest is not valid JSON');
  }
}

export function validateVerificationManifest(input, expected) {
  let manifest = input;
  if (typeof input === 'string' || Buffer.isBuffer(input)) {
    const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
    if (bytes.length > MAX_MANIFEST_BYTES) reject('manifest size exceeds the limit');
    try { manifest = JSON.parse(bytes.toString('utf8')); } catch { reject('manifest is not valid JSON'); }
  }
  object(manifest, 'manifest', [
    'schemaVersion', 'repository', 'event', 'pullRequestNumber', 'queueRef', 'queueParentSha',
    'baseSha', 'headSha', 'candidateSha', 'verifier', 'profile', 'run', 'checks',
  ]);
  if (manifest.schemaVersion !== 1) reject('manifest schemaVersion is unsupported');
  object(manifest.repository, 'manifest.repository', ['id', 'fullName']);
  exact(manifest.repository.id, expected.repository.id, 'repository id');
  exact(manifest.repository.fullName, expected.repository.fullName, 'repository name');
  exact(manifest.event, expected.event, 'event');
  exact(manifest.pullRequestNumber, expected.pullRequestNumber ?? null, 'pull request number');
  exact(manifest.queueRef ?? null, expected.queueRef ?? null, 'merge queue ref');
  exact(manifest.queueParentSha ?? null, expected.queueParentSha ?? null, 'merge queue parent SHA');
  for (const field of ['baseSha', 'headSha', 'candidateSha']) {
    if (!isSha(manifest[field])) reject(`manifest.${field} must be a full commit SHA`);
    exact(manifest[field], expected[field], field);
  }
  object(manifest.verifier, 'manifest.verifier', ['repository', 'path', 'sha']);
  exact(manifest.verifier.repository, expected.verifierRepository, 'verifier repository');
  exact(manifest.verifier.path, expected.verifierPath, 'verifier path');
  if (!isSha(manifest.verifier.sha)) reject('manifest verifier SHA must be a full commit SHA');
  exact(manifest.verifier.sha, expected.verifierSha, 'verifier SHA');
  object(manifest.profile, 'manifest.profile', ['id', 'sha256']);
  exact(manifest.profile.id, expected.profile.profileId, 'profile id');
  if (typeof manifest.profile.sha256 !== 'string' || !SHA_64.test(manifest.profile.sha256)) reject('manifest profile digest must be SHA-256');
  exact(manifest.profile.sha256, expected.profile.profileDigest, 'profile digest');
  object(manifest.run, 'manifest.run', ['id', 'attempt', 'checkSuiteId']);
  exact(String(manifest.run.id), String(expected.runId), 'run id');
  exact(manifest.run.attempt, expected.attempt, 'run attempt');
  exact(String(manifest.run.checkSuiteId), String(expected.checkSuiteId), 'check suite id');
  if (!Array.isArray(manifest.checks)) reject('manifest checks must be an array');
  const required = new Map(expected.profile.checks.map(check => [check.id, check]));
  const seen = new Set();
  const validated = [];
  for (const [index, result] of manifest.checks.entries()) {
    object(result, `manifest.checks[${index}]`, ['id', 'status', 'count', 'summary']);
    if (typeof result.id !== 'string' || !required.has(result.id)) reject(`manifest has unknown check ${String(result.id)}`);
    if (seen.has(result.id)) reject(`manifest has duplicate check ${result.id}`);
    seen.add(result.id);
    const definition = required.get(result.id);
    exact(result.status, 'passed', `${result.id} must pass`);
    if (!Number.isSafeInteger(result.count) || result.count < definition.minimumCount) reject(`${result.id} count is below minimum`);
    if (typeof result.summary !== 'string' || !result.summary.trim() || result.summary.length > 320 || /[\r\n\0]/.test(result.summary)) reject(`${result.id} summary is invalid`);
    validated.push({ id: result.id, status: 'passed', count: result.count, summary: result.summary });
  }
  if (seen.size !== required.size || [...required.keys()].some(id => !seen.has(id))) reject('manifest check inventory is incomplete');
  return validated;
}

function exactCallerText(expected) {
  if (typeof expected.callerTemplate !== 'string' || typeof expected.callerWorkflowText !== 'string') reject('caller workflow source is unavailable');
  const expectedText = expected.callerTemplate.replaceAll('{{VERIFIER_SHA}}', expected.verifierSha);
  const actualText = expected.callerWorkflowText.replace(/\r\n/g, '\n');
  if (actualText !== expectedText.replace(/\r\n/g, '\n')) reject('caller workflow does not match the fixed template');
}

export function verifyCentralWorkflowRun(run, jobs, checkRuns, artifact, expected) {
  exactCallerText(expected);
  if (String(run?.id ?? '') !== String(expected.runId)) reject('workflow run id does not match');
  if (Number(run?.run_attempt) !== expected.attempt) reject('workflow run attempt does not match');
  if (String(run?.check_suite_id ?? '') !== String(expected.checkSuiteId)) reject('workflow run check suite does not match');
  exact(run?.event, expected.event, 'workflow run event');
  exact(run?.head_sha, expected.event === 'pull_request' ? expected.headSha : expected.candidateSha, 'workflow run head SHA');
  exact(run?.path, expected.callerPath, 'caller workflow path');
  if (run?.status !== 'completed' || run?.conclusion !== 'success') reject('workflow run did not complete successfully');
  if (expected.event === 'pull_request') {
    const pullRequest = (Array.isArray(run?.pull_requests) ? run.pull_requests : []).find(item => Number(item?.number) === expected.pullRequestNumber);
    if (!pullRequest || pullRequest.base?.sha !== expected.baseSha || pullRequest.head?.sha !== expected.headSha) reject('workflow run pull request snapshot is stale');
  } else if (expected.event === 'merge_group') {
    exact(run?.head_branch, expected.queueRef, 'workflow run merge queue ref');
  } else reject('workflow run event is unsupported');

  if (!Array.isArray(run?.referenced_workflows) || run.referenced_workflows.length !== 1) reject('nested workflow reference inventory is invalid');
  const reference = run.referenced_workflows[0];
  const qualifiedPath = `${expected.verifierRepository}/${expected.verifierPath}@${expected.verifierSha}`;
  exact(reference?.path, qualifiedPath, 'nested workflow path');
  exact(reference?.sha, expected.verifierSha, 'nested workflow SHA');

  if (!Array.isArray(jobs)) reject('workflow job inventory is unavailable');
  const required = new Set(expected.profile.checks.map(check => check.id));
  const requiredJobs = new Set([...required, 'publish-verification-manifest']);
  const seenJobs = new Set();
  for (const job of jobs) {
    if (typeof job?.name !== 'string' || !requiredJobs.has(job.name)) reject(`workflow has unknown job ${String(job?.name)}`);
    if (seenJobs.has(job.name)) reject(`workflow has duplicate job ${job.name}`);
    seenJobs.add(job.name);
    if (String(job.run_id ?? expected.runId) !== String(expected.runId) || Number(job.run_attempt ?? expected.attempt) !== expected.attempt) reject(`workflow job ${job.name} belongs to the wrong run attempt`);
    if (job.status !== 'completed' || job.conclusion !== 'success') reject(`workflow job ${job.name} did not complete successfully`);
  }
  if (seenJobs.size !== requiredJobs.size || [...requiredJobs].some(id => !seenJobs.has(id))) reject('workflow job inventory is incomplete');

  if (!Array.isArray(checkRuns)) reject('GitHub check-run inventory is unavailable');
  const checkSeen = new Set();
  for (const check of checkRuns) {
    if (String(check?.check_suite?.id ?? '') !== String(expected.checkSuiteId)) continue;
    if (typeof check?.name !== 'string' || !required.has(check.name)) continue;
    if (checkSeen.has(check.name)) reject(`GitHub has duplicate check run ${check.name}`);
    checkSeen.add(check.name);
    const allowedCheckShas = expected.event === 'pull_request'
      ? new Set([expected.candidateSha, expected.headSha])
      : new Set([expected.candidateSha]);
    if (!allowedCheckShas.has(check.head_sha) || String(check.check_suite?.id ?? '') !== String(expected.checkSuiteId) || check.status !== 'completed' || check.conclusion !== 'success' || check.app?.slug !== 'github-actions') {
      reject(`GitHub check run ${check.name} is not a successful current-candidate Actions check or has the wrong check suite`);
    }
  }
  if (checkSeen.size !== required.size || [...required].some(id => !checkSeen.has(id))) reject('GitHub check-run inventory is incomplete');
  const manifest = Buffer.isBuffer(artifact) || artifact instanceof Uint8Array
    ? parseVerificationArtifact(artifact)
    : artifact;
  return validateVerificationManifest(manifest, expected);
}

export function sha256Profile(profile) {
  return createHash('sha256').update(JSON.stringify(profile)).digest('hex');
}
