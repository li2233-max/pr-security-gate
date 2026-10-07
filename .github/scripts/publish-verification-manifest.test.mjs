import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const publisher = fileURLToPath(new URL('./publish-verification-manifest.mjs', import.meta.url));
const baseSha = 'a'.repeat(40);
const headSha = 'b'.repeat(40);
const candidateSha = 'c'.repeat(40);
const verifierSha = 'd'.repeat(40);

async function publish(t, { queue = false, runHeadSha, currentCandidateSha = candidateSha } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'prsg-manifest-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const event = queue
    ? { action: 'checks_requested', merge_group: { head_sha: candidateSha, base_sha: baseSha, head_ref: 'refs/heads/gh-readonly-queue/main/pr-6' } }
    : { number: 6, pull_request: { head: { sha: headSha }, base: { sha: baseSha } } };
  const eventPath = join(directory, 'event.json');
  await writeFile(eventPath, JSON.stringify(event));
  const repositoryPath = '/repos/li2233-max/weixin';
  const responses = new Map([
    [repositoryPath, { id: 1378303598 }],
    [`${repositoryPath}/actions/runs/500`, { id: 500, run_attempt: 1, check_suite_id: 600, head_sha: runHeadSha ?? (queue ? candidateSha : headSha) }],
    [`${repositoryPath}/pulls/6`, { state: 'open', merge_commit_sha: currentCandidateSha, head: { sha: headSha }, base: { sha: baseSha } }],
  ]);
  const server = createServer((request, response) => {
    const payload = responses.get(request.url);
    response.writeHead(payload ? 200 : 404, { 'content-type': 'application/json' });
    response.end(JSON.stringify(payload ?? { message: 'Unexpected request' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const child = spawn(process.execPath, [publisher], {
    cwd: directory,
    env: {
      ...process.env,
      GITHUB_API_URL: `http://127.0.0.1:${server.address().port}`,
      GITHUB_REPOSITORY: 'li2233-max/weixin',
      GITHUB_EVENT_NAME: queue ? 'merge_group' : 'pull_request',
      GITHUB_EVENT_PATH: eventPath,
      GITHUB_SHA: candidateSha,
      GITHUB_TOKEN: 'test-token',
      GITHUB_RUN_ID: '500',
      GITHUB_RUN_ATTEMPT: '1',
      VERIFIER_SHA: verifierSha,
      SECRET_SCAN_COUNT: '3',
      DEPENDENCY_SCAN_COUNT: '2',
      PRODUCTION_HARDENING_TESTS_COUNT: '7',
    },
  });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.stdout.resume();
  const code = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', resolve);
  });
  return { code, stderr, manifestPath: join(directory, 'verification.json') };
}

test('publishes PR evidence with distinct run head and candidate merge SHAs', { timeout: 10000 }, async t => {
  const result = await publish(t);
  assert.equal(result.code, 0, result.stderr);
  const manifest = JSON.parse(await readFile(result.manifestPath, 'utf8'));
  assert.equal(manifest.headSha, headSha);
  assert.equal(manifest.candidateSha, candidateSha);
  assert.equal(manifest.baseSha, baseSha);
  assert.equal(manifest.verifier.sha, verifierSha);
  assert.deepEqual(manifest.run, { id: '500', attempt: 1, checkSuiteId: '600' });
  assert.deepEqual(manifest.checks.map(({ id, count }) => ({ id, count })), [
    { id: 'secret-scan', count: 3 },
    { id: 'dependency-scan', count: 2 },
    { id: 'production-hardening-tests', count: 7 },
  ]);
});

test('rejects a run whose head SHA no longer matches the PR event', { timeout: 10000 }, async t => {
  const result = await publish(t, { runHeadSha: candidateSha });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /workflow run head SHA does not match the event snapshot/);
  await assert.rejects(readFile(result.manifestPath), { code: 'ENOENT' });
});

test('rejects a PR whose candidate merge SHA changed before publication', { timeout: 10000 }, async t => {
  const result = await publish(t, { currentCandidateSha: 'e'.repeat(40) });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /pull request changed before manifest publication/);
  await assert.rejects(readFile(result.manifestPath), { code: 'ENOENT' });
});

test('publishes merge queue evidence when run head equals queue candidate SHA', { timeout: 10000 }, async t => {
  const result = await publish(t, { queue: true });
  assert.equal(result.code, 0, result.stderr);
  const manifest = JSON.parse(await readFile(result.manifestPath, 'utf8'));
  assert.equal(manifest.event, 'merge_group');
  assert.equal(manifest.headSha, candidateSha);
  assert.equal(manifest.candidateSha, candidateSha);
  assert.equal(manifest.queueParentSha, baseSha);
});
