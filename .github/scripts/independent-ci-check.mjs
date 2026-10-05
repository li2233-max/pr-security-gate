import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseVerificationProfile } from '../../profiles/verification-profile.mjs';

const verifierRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const profile = parseVerificationProfile(JSON.parse(readFileSync(join(verifierRoot, 'profiles/weixin-ci-verification.json'), 'utf8')));
const candidateRoot = resolve(process.env.CANDIDATE_PATH ?? join(process.env.GITHUB_WORKSPACE ?? '', '.candidate'));
const checkId = process.env.VERIFICATION_CHECK_ID;
const sourceRef = process.env.GITHUB_SHA;
const repository = process.env.GITHUB_REPOSITORY;
const apiBase = process.env.GITHUB_API_URL ?? 'https://api.github.com';
const githubToken = process.env.GITHUB_TOKEN;
const MAX_SNAPSHOT_FILE_COUNT = 50_000;
const MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024;
const MAX_SNAPSHOT_FILE_BYTES = 64 * 1024 * 1024;

function fail(message) {
  throw new Error(message);
}

function safeRun(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'buffer',
    timeout: 240_000,
    maxBuffer: 4 * 1024 * 1024,
    env: { PATH: process.env.PATH ?? '', HOME: process.env.RUNNER_TEMP ?? tmpdir() },
    ...options,
  });
  if (result.error) fail(`${command} could not complete (${result.error.code ?? 'spawn-error'})`);
  return result;
}

function outputText(value) {
  return Buffer.isBuffer(value) ? value.toString('utf8') : String(value ?? '');
}

export function summarizeProcessFailure(label, result) {
  const stdout = outputText(result.stdout);
  const stderr = outputText(result.stderr);
  const tests = [...stdout.matchAll(/^not ok \d+ - ([^\r\n(]{1,120})/gm)]
    .map(([, name]) => name.replace(/[^A-Za-z0-9 _./:-]/g, '?').trim())
    .filter(Boolean)
    .slice(0, 3);
  const errorCode = `${stdout}\n${stderr}`.match(/\b(EAI_AGAIN|ENOTFOUND|EAI_FAIL|ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENETUNREACH|EACCES|EPERM|EROFS|ENOENT)\b/)?.[1];
  const filesystemIssue = /read-only file system/i.test(`${stdout}\n${stderr}`);
  const exit = Number.isInteger(result.status) ? `exit code ${result.status}` : `signal ${String(result.signal ?? 'unknown')}`;
  const details = [];
  if (tests.length) details.push(`failed test cases: ${tests.join('; ')}`);
  if (errorCode) details.push(`process error: ${errorCode}`);
  if (filesystemIssue && !errorCode) details.push('process error: read-only filesystem');
  return `${label} failed with ${exit}${details.length ? ` (${details.join('; ')})` : ''}`;
}

function requireSuccess(result, label) {
  if (result.status !== 0) fail(`${label} failed with exit code ${result.status ?? 'unknown'}`);
}

function githubHeaders() {
  if (!githubToken) fail('GitHub read token is unavailable');
  return {
    accept: 'application/vnd.github+json',
    authorization: `Bearer ${githubToken}`,
    'x-github-api-version': '2022-11-28',
  };
}

async function readApi(url, label) {
  let response;
  try {
    response = await fetch(url, { headers: githubHeaders(), redirect: 'error' });
  } catch {
    fail(`${label} could not be fetched`);
  }
  if (!response.ok) fail(`${label} returned HTTP ${response.status}`);
  return response.json();
}

function readEvent() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath || !existsSync(eventPath)) fail('GitHub event payload is unavailable');
  return JSON.parse(readFileSync(eventPath, 'utf8'));
}

async function assertCandidateFresh() {
  if (repository !== profile.repository.fullName || !sourceRef || !/^[a-f0-9]{40}$/.test(sourceRef)) fail('repository or candidate SHA is not approved');
  const repo = await readApi(`${apiBase}/repos/${profile.repository.fullName}`, 'repository identity');
  if (Number(repo.id) !== profile.repository.id) fail('repository ID is not approved');
  const event = readEvent();
  const eventName = process.env.GITHUB_EVENT_NAME;
  if (!profile.events.includes(eventName)) fail('event is not supported by this profile');
  if (eventName === 'pull_request') {
    const number = Number(event.number);
    if (!Number.isSafeInteger(number) || number < 1) fail('pull request number is invalid');
    const current = await readApi(`${apiBase}/repos/${profile.repository.fullName}/pulls/${number}`, 'current pull request');
    if (current.state !== 'open' || current.base?.sha !== event.pull_request?.base?.sha || current.head?.sha !== event.pull_request?.head?.sha || current.merge_commit_sha !== sourceRef) {
      fail('pull request base, head, state or merge candidate changed');
    }
    return { eventName, number, baseSha: current.base.sha, headSha: current.head.sha, candidateSha: sourceRef, queueRef: null, queueParentSha: null };
  }
  if (eventName === 'merge_group') {
    const group = event.merge_group;
    if (event.action !== 'checks_requested' || !group || group.head_sha !== sourceRef || !/^[a-f0-9]{40}$/.test(group.base_sha ?? '')) fail('merge queue candidate identity is invalid');
    const parents = safeRun('git', ['-C', candidateRoot, 'rev-list', '--parents', '-n', '1', sourceRef]);
    requireSuccess(parents, 'merge queue ancestry check');
    const parentShas = parents.stdout.toString('utf8').trim().split(/\s+/).slice(1);
    if (!parentShas.includes(group.base_sha)) fail('merge queue candidate does not contain the declared parent');
    return { eventName, number: null, baseSha: group.base_sha, headSha: sourceRef, candidateSha: sourceRef, queueRef: group.head_ref, queueParentSha: group.base_sha };
  }
  fail('event is unsupported');
}

export function parseTreeEntries(treeOutput) {
  const rows = [];
  let offset = 0;
  while (offset < treeOutput.length) {
    const end = treeOutput.indexOf(0, offset);
    if (end < 0) fail('candidate tree output is truncated');
    if (end > offset) rows.push(treeOutput.subarray(offset, end));
    offset = end + 1;
  }
  if (rows.length === 0 || rows.length > MAX_SNAPSHOT_FILE_COUNT) fail('candidate tree is empty or exceeds the file-count limit');
  return rows.map(row => {
    const separator = row.indexOf(0x09);
    if (separator < 0) fail('candidate tree entry is malformed');
    const [mode, type, sha] = row.subarray(0, separator).toString('ascii').split(' ');
    const pathBytes = row.subarray(separator + 1);
    const path = pathBytes.toString('utf8');
    if (type !== 'blob' || !['100644', '100755'].includes(mode) || !/^[a-f0-9]{40}$/.test(sha ?? '')) {
      fail('candidate contains a symbolic link, submodule or unsupported tree entry');
    }
    if (!path || path.includes('\\') || /[\u0000-\u001f\u007f]/.test(path) ||
        !Buffer.from(path, 'utf8').equals(pathBytes) || path.split('/').some(part => !part || part === '.' || part === '..')) {
      fail('candidate contains an unsafe or non-UTF-8 path');
    }
    return { mode, sha, path };
  });
}

export function prepareSnapshotForDocker(snapshot) {
  const makeDirectoriesTraversable = (directory) => {
    chmodSync(directory, 0o755);
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const child = join(directory, entry.name);
      const stat = lstatSync(child);
      if (stat.isSymbolicLink()) fail('candidate snapshot contains a symbolic link');
      if (stat.isDirectory()) makeDirectoriesTraversable(child);
      else if (stat.isFile()) chmodSync(child, stat.mode & 0o111 ? 0o555 : 0o444);
    }
  };
  makeDirectoriesTraversable(snapshot);
}

function walkFiles(root, relative = '') {
  const directory = join(root, relative);
  const results = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const child = relative ? `${relative}/${entry.name}` : entry.name;
    const absolute = join(root, child);
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) fail('candidate snapshot contains a symbolic link');
    if (stat.isDirectory()) results.push(...walkFiles(root, child));
    else if (stat.isFile()) results.push(child.replaceAll('\\', '/'));
  }
  return results;
}

function createSnapshot(parent) {
  const tree = safeRun('git', ['-C', candidateRoot, 'ls-tree', '-rz', '--full-tree', sourceRef]);
  requireSuccess(tree, 'candidate tree inspection');
  const entries = parseTreeEntries(tree.stdout);
  const snapshot = mkdtempSync(join(parent, 'candidate-'));
  let totalBytes = 0;
  for (const entry of entries) {
    const blob = safeRun('git', ['-C', candidateRoot, 'cat-file', 'blob', entry.sha], { maxBuffer: MAX_SNAPSHOT_FILE_BYTES });
    requireSuccess(blob, 'candidate blob read');
    totalBytes += blob.stdout.length;
    if (blob.stdout.length > MAX_SNAPSHOT_FILE_BYTES || totalBytes > MAX_SNAPSHOT_BYTES) fail('candidate snapshot exceeds the byte-size limit');
    const destination = resolve(snapshot, ...entry.path.split('/'));
    const relativePath = destination.slice(snapshot.length + 1);
    if (!relativePath || relativePath.startsWith(`..${sep}`) || relativePath === '..') fail('candidate path escaped the isolated snapshot');
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, blob.stdout, { mode: entry.mode === '100755' ? 0o555 : 0o444, flag: 'wx' });
  }
  for (const file of walkFiles(snapshot)) {
    if (['.gitignore', '.semgrepignore', '.gitleaksignore', '.gitleaks.toml', '.npmrc'].includes(file.split('/').at(-1))) {
      rmSync(join(snapshot, ...file.split('/')), { force: true });
    }
  }
  prepareSnapshotForDocker(snapshot);
  return snapshot;
}

function scanTargets(snapshot) {
  const files = walkFiles(snapshot);
  const roots = profile.scanRoots.filter(root => existsSync(join(snapshot, ...root.split('/'))));
  if (roots.length === 0) fail('no approved scan roots exist in the candidate');
  const targets = files.filter(file => roots.some(root => file === root || file.startsWith(`${root}/`)));
  if (targets.length < 1) fail('scan targets are empty');
  return { roots, count: targets.length };
}

async function withTemp(work) {
  const temp = mkdtempSync(join(process.env.RUNNER_TEMP ?? tmpdir(), 'prsg-independent-'));
  try { return await work(temp); } finally { rmSync(temp, { recursive: true, force: true }); }
}

function dockerBase(image, candidate, { network = 'none', extraMounts = [], entrypoint, commandArgs = [], workdir } = {}) {
  const args = [
    'run', '--rm', '--network', network, '--read-only', '--user', '65532:65532',
    '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=1g', '--cpus=2',
    '--tmpfs=/tmp:rw,noexec,nosuid,size=128m', '-e', 'HOME=/tmp',
    '--mount', `type=bind,src=${candidate},dst=/src,readonly`,
  ];
  for (const [host, container] of extraMounts) args.push('--mount', `type=bind,src=${host},dst=${container},readonly`);
  if (workdir) args.push('--workdir', workdir);
  if (entrypoint) args.push('--entrypoint', entrypoint);
  args.push(image);
  args.push(...commandArgs);
  return args;
}

async function downloadBytes(url, maxBytes) {
  let response;
  try { response = await fetch(url, { redirect: 'follow' }); } catch { fail('pinned scanner artifact could not be fetched'); }
  if (!response.ok) fail(`pinned scanner artifact returned HTTP ${response.status}`);
  const advertised = Number(response.headers.get('content-length') ?? 0);
  if (advertised > maxBytes) fail('pinned scanner artifact exceeds its size limit');
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > maxBytes) fail('pinned scanner artifact exceeds its size limit');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

async function runSecretScan(snapshot) {
  const targets = scanTargets(snapshot);
  const tool = profile.tools.gitleaks;
  const asset = `https://github.com/gitleaks/gitleaks/releases/download/v${tool.version}/gitleaks_${tool.version}_${tool.platform}.tar.gz`;
  const archive = await downloadBytes(asset, 25 * 1024 * 1024);
  const digest = createHash('sha256').update(archive).digest('hex');
  if (digest !== tool.archiveSha256) fail('pinned Gitleaks archive checksum does not match');
  const temp = mkdtempSync(join(process.env.RUNNER_TEMP ?? tmpdir(), 'prsg-gitleaks-'));
  try {
    const archivePath = join(temp, 'gitleaks.tar.gz');
    writeFileSync(archivePath, archive, { mode: 0o600 });
    const list = safeRun('tar', ['-tzf', archivePath]);
    requireSuccess(list, 'Gitleaks archive inventory');
    const names = list.stdout.toString('utf8').trim().split(/\r?\n/);
    if (!names.includes('gitleaks') || names.some(name => name.includes('/') || name.startsWith('.'))) fail('Gitleaks archive contains an unexpected path');
    const unpack = safeRun('tar', ['-xzf', archivePath, '-C', temp]);
    requireSuccess(unpack, 'Gitleaks archive extraction');
    const report = join(temp, 'report.json');
    const scan = safeRun(join(temp, 'gitleaks'), ['dir', '--redact', '--no-banner', '--no-color', '--exit-code', '1', '--report-format', 'json', '--report-path', report, snapshot]);
    if (!existsSync(report)) {
      if (scan.status !== 0) fail(summarizeProcessFailure('Gitleaks scan', scan));
      fail('Gitleaks did not create its required report');
    }
    const findings = JSON.parse(readFileSync(report, 'utf8'));
    if (!Array.isArray(findings)) fail('Gitleaks report schema is invalid');
    if (findings.length) {
      const rules = [...new Set(findings.map(item => item.RuleID).filter(value => /^[A-Za-z0-9_-]{1,60}$/.test(value ?? '')))].slice(0, 3);
      fail(`Gitleaks found ${findings.length} finding(s)${rules.length ? ` (${rules.join(', ')})` : ''}`);
    }
    if (scan.status !== 0) fail(summarizeProcessFailure('Gitleaks scan', scan));
    return targets.count;
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

export async function runSemgrep(snapshot) {
  const targets = scanTargets(snapshot);
  const rules = join(verifierRoot, 'profiles/weixin-semgrep-rules.yml');
  const rulesDigest = createHash('sha256').update(readFileSync(rules)).digest('hex');
  if (rulesDigest !== profile.tools.semgrep.rulesetSha256) fail('Semgrep ruleset digest does not match the fixed profile');
  const result = safeRun('docker', [
    ...dockerBase(profile.tools.semgrep.image, snapshot, {
      extraMounts: [[rules, '/rules.yml']],
      entrypoint: 'semgrep',
      workdir: '/src',
      commandArgs: ['scan', '--config', '/rules.yml', '--json', '--error', '--strict', '--metrics=off', '--disable-version-check', '--no-git-ignore', ...targets.roots],
    }),
  ]);
  let report;
  try { report = JSON.parse(result.stdout.toString('utf8')); } catch { fail('Semgrep output is not valid JSON'); }
  if (result.status !== 0) {
    if (Number.isSafeInteger(report?.results?.length) && report.results.length) {
      const locations = report.results.slice(0, 3).map(item => {
        const rule = /^[A-Za-z0-9_.-]{1,100}$/.test(item.check_id ?? '') ? item.check_id : 'security rule';
        const line = Number.isSafeInteger(item.start?.line) ? item.start.line : '?';
        return `${rule} at line ${line}`;
      });
      fail(`Semgrep found ${report.results.length} security finding(s): ${locations.join('; ')}`);
    }
    const errorKinds = Array.isArray(report?.errors)
      ? report.errors.map(error => `${String(error?.type ?? 'scanner error').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 40)}${Number.isSafeInteger(error?.code) ? `#${error.code}` : ''}`).filter(Boolean).slice(0, 3)
      : [];
    if (errorKinds.length) fail(`Semgrep scanner reported ${errorKinds.join(', ')}`);
    fail(summarizeProcessFailure('Semgrep scan', result));
  }
  if (!Array.isArray(report?.results)) fail('Semgrep report has no results list');
  if (!Array.isArray(report?.paths?.scanned) || report.paths.scanned.length === 0) {
    const skipped = Array.isArray(report?.paths?.skipped) ? report.paths.skipped.length : 0;
    fail(`Semgrep scanned 0 files from ${targets.count} approved targets (${skipped} skipped)`);
  }
  if (report.results.length) fail('Semgrep found one or more security issues');
  return report.paths.scanned.length;
}

async function runDependencyScan(snapshot) {
  const lock = 'miniprogram/package-lock.json';
  if (!existsSync(join(snapshot, ...lock.split('/')))) fail('the approved miniprogram package lockfile is missing');
  const audit = safeRun('docker', [
    ...dockerBase(profile.tools.nodeTest.image, snapshot, {
      network: 'bridge',
      entrypoint: 'npm',
      commandArgs: ['audit', '--prefix', '/src/miniprogram', '--omit=dev', '--audit-level=high', '--json', '--registry=https://registry.npmjs.org'],
    }),
  ]);
  let report;
  try { report = JSON.parse(audit.stdout.toString('utf8')); } catch {
    if (audit.status !== 0) fail(summarizeProcessFailure('npm audit', audit));
    fail('npm audit output is not valid JSON');
  }
  if (audit.status !== 0) {
    const vulnerabilities = report?.metadata?.vulnerabilities;
    if (Number.isSafeInteger(vulnerabilities?.total) && vulnerabilities.total > 0) {
      fail(`npm audit found ${vulnerabilities.total} vulnerability/vulnerabilities (high=${vulnerabilities.high ?? 0}, critical=${vulnerabilities.critical ?? 0})`);
    }
    const registryCode = /^[A-Z0-9_]{1,40}$/.test(report?.error?.code ?? '') ? report.error.code : null;
    if (registryCode) fail(`npm audit reported a registry error (${registryCode})`);
    fail(summarizeProcessFailure('npm audit', audit));
  }
  if (!Number.isSafeInteger(report?.metadata?.dependencies?.prod)) fail('npm audit report is incomplete');
  return Math.max(1, report.metadata.dependencies.prod);
}

async function trustedTestFiles(check) {
  const suite = profile.trustedTests.find(item => item.checkId === check);
  if (!suite) fail('trusted test suite is not registered');
  const result = [];
  for (const file of suite.files) {
    const url = `${apiBase}/repos/${profile.repository.fullName}/contents/${file.path.split('/').map(encodeURIComponent).join('/')}?ref=${suite.sourceCommit}`;
    const payload = await readApi(url, 'approved private test source');
    if (payload.encoding !== 'base64' || typeof payload.content !== 'string') fail('approved private test source is not a base64 blob');
    const bytes = Buffer.from(payload.content.replace(/\s/g, ''), 'base64');
    if (bytes.length > 128 * 1024 || createHash('sha256').update(bytes).digest('hex') !== file.sha256) fail('approved private test source digest does not match');
    result.push({ ...file, bytes });
  }
  return result;
}

export function installTrustedTests(snapshot, files) {
  for (const file of files) {
    const target = resolve(snapshot, ...file.path.split('/'));
    const relative = target.slice(snapshot.length + 1);
    if (relative.startsWith(`..${sep}`) || relative === '..') fail('approved test path escaped the sandbox source');
    mkdirSync(dirname(target), { recursive: true });
    rmSync(target, { force: true });
    writeFileSync(target, file.bytes, { mode: 0o444, flag: 'wx' });
    chmodSync(target, 0o444);
  }
}

async function runTrustedTests(snapshot, files) {
  installTrustedTests(snapshot, files);
  prepareSnapshotForDocker(snapshot);
  const result = safeRun('docker', [
    ...dockerBase(profile.tools.nodeTest.image, snapshot, {
      entrypoint: 'node',
      commandArgs: ['--test', ...files.map(file => `/src/${file.path}`)],
    }),
  ]);
  if (result.status !== 0) fail(summarizeProcessFailure('trusted tests in the isolated container', result));
  return files.length;
}

function productionHardeningCount(snapshot) {
  const appJsonPath = join(snapshot, 'miniprogram/app.json');
  const runtimePath = join(snapshot, 'miniprogram/configs/runtime.js');
  const qualityWorkflowPath = join(snapshot, '.github/workflows/quality.yml');
  if (!existsSync(appJsonPath) || !existsSync(runtimePath) || !existsSync(qualityWorkflowPath)) fail('required production or CI control file is missing');
  let app;
  try { app = JSON.parse(readFileSync(appJsonPath, 'utf8')); } catch { fail('miniprogram app.json is invalid'); }
  const runtime = readFileSync(runtimePath, 'utf8');
  const workflow = readFileSync(qualityWorkflowPath, 'utf8');
  const checks = [
    app.pages?.includes('pages/privacy/privacy') === true,
    /paymentEnabled\s*:\s*false/.test(runtime),
    /allowLocalFallback\s*:\s*false/.test(runtime),
    !/^\s*pull_request_target\s*:/m.test(workflow),
    !/^\s*secrets\s*:\s*inherit\s*$/m.test(workflow),
    !/^\s*permissions\s*:\s*(?:write-all|\{[^}]*write)/m.test(workflow),
    !/^\s*- *uses:\s*[^\s#]+@(?![a-f0-9]{40}\b)[^\s#]+/mi.test(workflow),
  ];
  if (checks.some(check => !check)) fail('production or CI hardening policy failed');
  return checks.length;
}

async function runCheck(temp) {
  const definition = profile.checks.find(item => item.id === checkId);
  if (!definition) fail('verification check ID is not in the fixed profile');
  const freshness = await assertCandidateFresh();
  const runTree = safeRun('git', ['-C', candidateRoot, 'rev-parse', '--verify', 'HEAD']);
  requireSuccess(runTree, 'candidate checkout validation');
  if (runTree.stdout.toString('utf8').trim() !== sourceRef) fail('candidate checkout does not match the current event SHA');
  const snapshot = createSnapshot(temp);
  let count;
  if (checkId === 'secret-scan') count = await runSecretScan(snapshot);
  else if (checkId === 'sast-config-scan') count = await runSemgrep(snapshot);
  else if (checkId === 'dependency-scan') count = await runDependencyScan(snapshot);
  else if (checkId === 'payment-refund-tests' || checkId === 'authorization-tests') count = await runTrustedTests(snapshot, await trustedTestFiles(checkId));
  else if (checkId === 'production-hardening-tests') count = productionHardeningCount(snapshot);
  else fail('verification check implementation is missing');
  if (!Number.isSafeInteger(count) || count < definition.minimumCount) fail('verified target/test count is below the fixed minimum');
  if (!process.env.GITHUB_OUTPUT) fail('GitHub job output file is unavailable');
  writeFileSync(process.env.GITHUB_OUTPUT, `count=${count}\nsummary=${definition.id} passed on ${freshness.candidateSha}\n`, { flag: 'a' });
}

async function main() {
  await withTemp(temp => runCheck(temp));
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => {
    // Never echo candidate-controlled scanner/test output into the runner command channel.
    console.error(String(error?.message ?? 'independent verification failed').replace(/[\r\n]/g, ' ').slice(0, 300));
    process.exitCode = 1;
  });
}
