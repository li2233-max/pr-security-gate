import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseVerificationProfile } from '../../profiles/verification-profile.mjs';
import { readFileSync } from 'node:fs';

const verifierRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const profile = parseVerificationProfile(JSON.parse(readFileSync(resolve(verifierRoot, 'profiles/weixin-ci-verification.json'), 'utf8')));

function fail(message) {
  throw new Error(message);
}

export function workflowRunHeadSha(eventName, event, candidateSha) {
  const value = eventName === 'pull_request'
    ? event?.pull_request?.head?.sha
    : eventName === 'merge_group'
      ? candidateSha
      : null;
  if (!/^[a-f0-9]{40}$/.test(value ?? '')) fail('workflow run head SHA is invalid for the event');
  return value;
}

function positiveCount(value, label) {
  if (!/^\d+$/.test(String(value ?? ''))) fail(`${label} is missing`);
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < 1) fail(`${label} is invalid`);
  return count;
}

async function readJson(url, token, label) {
  let response;
  try {
    response = await fetch(url, {
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'x-github-api-version': '2022-11-28',
      },
      redirect: 'error',
    });
  } catch {
    fail(`${label} could not be fetched`);
  }
  if (!response.ok) fail(`${label} returned HTTP ${response.status}`);
  return response.json();
}

async function main() {
  const repoName = process.env.GITHUB_REPOSITORY;
  const eventName = process.env.GITHUB_EVENT_NAME;
  const candidateSha = process.env.GITHUB_SHA;
  const token = process.env.GITHUB_TOKEN;
  const verifierSha = process.env.VERIFIER_SHA;
  const runId = process.env.GITHUB_RUN_ID;
  const attempt = Number(process.env.GITHUB_RUN_ATTEMPT);
  if (repoName !== profile.repository.fullName || !token || !/^[a-f0-9]{40}$/.test(candidateSha ?? '') || !/^[a-f0-9]{40}$/.test(verifierSha ?? '')) {
    fail('repository, token, candidate or verifier identity is invalid');
  }
  if (!profile.events.includes(eventName) || !/^\d+$/.test(runId ?? '') || !Number.isSafeInteger(attempt) || attempt < 1) fail('event or workflow run identity is invalid');

  const apiBase = process.env.GITHUB_API_URL ?? 'https://api.github.com';
  const [repo, run] = await Promise.all([
    readJson(`${apiBase}/repos/${profile.repository.fullName}`, token, 'repository identity'),
    readJson(`${apiBase}/repos/${profile.repository.fullName}/actions/runs/${runId}`, token, 'current workflow run'),
  ]);
  if (Number(repo.id) !== profile.repository.id || String(run.id) !== runId || Number(run.run_attempt) !== attempt) {
    fail('repository or workflow run snapshot changed');
  }
  const checks = profile.checks.map(check => {
    const envName = check.id.replace(/-/g, '_').toUpperCase() + '_COUNT';
    const count = positiveCount(process.env[envName], envName);
    if (count < check.minimumCount) fail(`${check.id} output count is below its minimum`);
    return { id: check.id, status: 'passed', count, summary: `${check.id} passed` };
  });

  let pullRequestNumber = null;
  let baseSha;
  let headSha;
  let queueRef = null;
  let queueParentSha = null;
  const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const runHeadSha = workflowRunHeadSha(eventName, event, candidateSha);
  if (run.head_sha !== runHeadSha) fail('workflow run head SHA does not match the event snapshot');
  if (eventName === 'pull_request') {
    pullRequestNumber = Number(event.number);
    if (!Number.isSafeInteger(pullRequestNumber) || pullRequestNumber < 1) fail('pull request number is invalid');
    const current = await readJson(`${apiBase}/repos/${profile.repository.fullName}/pulls/${pullRequestNumber}`, token, 'current pull request');
    if (current.state !== 'open' || current.merge_commit_sha !== candidateSha || current.base?.sha !== event.pull_request?.base?.sha || current.head?.sha !== event.pull_request?.head?.sha) {
      fail('pull request changed before manifest publication');
    }
    baseSha = current.base.sha;
    headSha = current.head.sha;
  } else {
    const group = event.merge_group;
    if (event.action !== 'checks_requested' || group?.head_sha !== candidateSha || !/^[a-f0-9]{40}$/.test(group?.base_sha ?? '')) fail('merge queue identity changed before manifest publication');
    baseSha = group.base_sha;
    headSha = group.head_sha;
    queueRef = group.head_ref;
    queueParentSha = group.base_sha;
  }
  if (!/^\d+$/.test(String(run.check_suite_id ?? ''))) fail('workflow run check suite identity is invalid');
  const manifest = {
    schemaVersion: 1,
    repository: { id: profile.repository.id, fullName: profile.repository.fullName },
    event: eventName,
    pullRequestNumber,
    queueRef,
    queueParentSha,
    baseSha,
    headSha,
    candidateSha,
    verifier: {
      repository: 'li2233-max/pr-security-gate',
      path: '.github/workflows/independent-ci-verification.yml',
      sha: verifierSha,
    },
    profile: { id: profile.profileId, sha256: profile.profileDigest },
    run: { id: runId, attempt, checkSuiteId: String(run.check_suite_id) },
    checks,
  };
  writeFileSync(resolve(process.cwd(), 'verification.json'), `${JSON.stringify(manifest)}\n`, { mode: 0o600, flag: 'wx' });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => {
    console.error(String(error?.message ?? 'manifest publication failed').replace(/[\r\n]/g, ' ').slice(0, 300));
    process.exitCode = 1;
  });
}
