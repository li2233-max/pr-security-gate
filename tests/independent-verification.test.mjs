import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createWorkflowDependencies } from '../.github/scripts/pr-ai-review.mjs';
import { parseVerificationProfile } from '../profiles/verification-profile.mjs';

function zipStored(filename, content) {
  const name = Buffer.from(filename);
  const data = Buffer.from(content);
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  crc = (crc ^ 0xffffffff) >>> 0;
  const local = Buffer.alloc(30 + name.length + data.length);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0x0800, 6);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(name.length, 26);
  name.copy(local, 30);
  data.copy(local, 30 + name.length);
  const central = Buffer.alloc(46 + name.length);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0x0800, 8);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(name.length, 28);
  name.copy(central, 46);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(local.length, 16);
  return Buffer.concat([local, central, end]);
}

test('accepts only the pinned weixin verifier run and candidate-bound manifest', async () => {
  const profile = parseVerificationProfile(JSON.parse(await readFile(new URL('../profiles/weixin-ci-verification.json', import.meta.url), 'utf8')));
  const callerTemplate = await readFile(new URL('../templates/project-independent-ci-verification.yml', import.meta.url), 'utf8');
  const verifierSha = '5a642e472743f4be2242b56eab6d81a98339ebba';
  const baseSha = '1'.repeat(40);
  const headSha = '2'.repeat(40);
  const candidateSha = '3'.repeat(40);
  const runId = '777';
  const checkSuiteId = '888';
  const callerPath = '.github/workflows/independent-ci-verification.yml';
  const callerText = callerTemplate.replace('{{VERIFIER_SHA}}', verifierSha);
  const checks = profile.checks.map(check => ({ id: check.id, status: 'passed', count: check.minimumCount, summary: `${check.id} passed` }));
  const manifest = {
    schemaVersion: 1,
    repository: profile.repository,
    event: 'pull_request',
    pullRequestNumber: 4,
    queueRef: null,
    queueParentSha: null,
    baseSha,
    headSha,
    candidateSha,
    verifier: { repository: 'li2233-max/pr-security-gate', path: '.github/workflows/independent-ci-verification.yml', sha: verifierSha },
    profile: { id: profile.profileId, sha256: profile.profileDigest },
    run: { id: runId, attempt: 1, checkSuiteId },
    checks,
  };
  const artifact = zipStored('verification.json', JSON.stringify(manifest));
  const jobs = [
    ...profile.checks.map(check => ({ name: check.id, status: 'completed', conclusion: 'success', run_id: Number(runId), run_attempt: 1 })),
    { name: 'publish-verification-manifest', status: 'completed', conclusion: 'success', run_id: Number(runId), run_attempt: 1 },
  ];
  const checkRuns = profile.checks.map((check, index) => ({
    id: 900 + index,
    name: check.id,
    head_sha: candidateSha,
    status: 'completed',
    conclusion: 'success',
    check_suite: { id: Number(checkSuiteId) },
    app: { slug: 'github-actions' },
    details_url: `https://github.com/li2233-max/weixin/actions/runs/${runId}/job/${901 + index}`,
    html_url: `https://github.com/li2233-max/weixin/actions/runs/${runId}`,
  }));
  let artifactExpired = false;
  const run = {
    id: Number(runId),
    run_number: 77,
    run_attempt: 1,
    check_suite_id: Number(checkSuiteId),
    event: 'pull_request',
    head_sha: headSha,
    path: callerPath,
    status: 'completed',
    conclusion: 'success',
    pull_requests: [{ number: 4, base: { sha: baseSha }, head: { sha: headSha } }],
    referenced_workflows: [{ path: `li2233-max/pr-security-gate/.github/workflows/independent-ci-verification.yml@${verifierSha}`, sha: verifierSha }],
  };
  const fetchImpl = async url => {
    if (url.includes(`/contents/${callerPath}?`)) return new Response(JSON.stringify({ type: 'file', encoding: 'base64', content: Buffer.from(callerText).toString('base64') }));
    if (url.includes('/actions/runs?head_sha=')) return new Response(JSON.stringify({ total_count: 1, workflow_runs: [run] }));
    if (url.endsWith(`/actions/runs/${runId}`)) return new Response(JSON.stringify(run));
    if (url.includes(`/actions/runs/${runId}/attempts/1/jobs`)) return new Response(JSON.stringify({ total_count: jobs.length, jobs }));
    if (url.endsWith(`/actions/runs/${runId}/artifacts?per_page=100&page=1`)) return new Response(JSON.stringify({
      total_count: 1,
      artifacts: [{ id: 999, name: 'independent-ci-verification-1', expired: artifactExpired, size_in_bytes: artifact.length }],
    }));
    if (url.endsWith('/actions/artifacts/999/zip')) return new Response(artifact);
    if (url.includes('/commits/') && url.includes('/check-runs')) {
      const items = url.includes(candidateSha) ? checkRuns : [];
      return new Response(JSON.stringify({ total_count: items.length, check_runs: items }));
    }
    if (url.includes('/commits/') && url.includes('/status')) return new Response(JSON.stringify({ total_count: 0, statuses: [] }));
    if (url.includes('/code-scanning/')) return new Response('forbidden', { status: 403 });
    if (url.endsWith('/pulls/4')) return new Response(JSON.stringify({
      number: 4, state: 'open', merge_commit_sha: candidateSha,
      base: { sha: baseSha }, head: { sha: headSha }, body: '',
    }));
    throw new Error(`unexpected GitHub API request: ${url}`);
  };
  const dependencies = createWorkflowDependencies({
    event: { number: 4, pull_request: { title: 'staff access', base: { ref: 'main', sha: baseSha }, head: { ref: 'feature/staff', sha: headSha, repo: { fork: false } }, merge_commit_sha: candidateSha } },
    env: { GITHUB_REPOSITORY: 'li2233-max/weixin', GITHUB_TOKEN: 'read-token', GITHUB_SHA: candidateSha, EVIDENCE_CHECK_WAIT_MS: '0' },
    fetchImpl,
    readFileImpl: async () => callerTemplate,
    policyRoot: '/policy',
  });

  const evidence = await dependencies.getEvidence();
  const verified = evidence.filter(item => item.producer === 'github-actions-independent-verifier');
  assert.equal(verified.length, profile.checks.length);
  assert.ok(verified.every(item => item.status === 'passed' && item.sha === candidateSha), JSON.stringify(verified));
  assert.equal(verified.find(item => item.name === 'authorization-tests').type, 'test');
  assert.equal(verified.find(item => item.name === 'payment-refund-tests').type, 'test');

  artifactExpired = true;
  const expiredEvidence = (await dependencies.getEvidence()).filter(item => item.producer === 'github-actions-independent-verifier');
  assert.equal(expiredEvidence.length, profile.checks.length);
  assert.ok(expiredEvidence.every(item => item.status === 'unavailable' && item.verified === false));
});
