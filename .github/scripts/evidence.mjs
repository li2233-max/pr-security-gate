import { createHash } from 'node:crypto';

export class EvidenceError extends Error {}

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new EvidenceError(`${label} 必须是对象`);
  }
  return value;
}

function requireText(value, label) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new EvidenceError(`${label} 必须是非空文本`);
  }
  return value.trim();
}

function requireHttpsUrl(value, label) {
  const text = requireText(value, label);
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    throw new EvidenceError(`${label} 必须是有效 URL`);
  }
  if (parsed.protocol !== 'https:') {
    throw new EvidenceError(`${label} 必须使用 HTTPS`);
  }
  return parsed.toString();
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function requireTextArray(value, label, { nonEmpty = false } = {}) {
  if (!Array.isArray(value) || (nonEmpty && value.length === 0)) {
    throw new EvidenceError(`${label} 必须是${nonEmpty ? '非空' : ''}数组`);
  }
  const result = value.map((item, index) => requireText(item, `${label}[${index}]`));
  if (new Set(result).size !== result.length) throw new EvidenceError(`${label} 不能包含重复项`);
  return result;
}

function requireRegex(value, label) {
  const pattern = requireText(value, label);
  try {
    new RegExp(pattern, 'i');
  } catch {
    throw new EvidenceError(`${label} 必须是有效正则表达式`);
  }
  return pattern;
}

function evidenceId(record) {
  const identity = [record.type, record.source, record.status, record.sha, record.url, record.name, record.producer ?? ''];
  return `ev_${createHash('sha256').update(JSON.stringify(identity)).digest('hex').slice(0, 16)}`;
}

export function validateEvidencePolicy(raw) {
  const policy = requireObject(raw, 'evidencePolicy');
  if (policy.schemaVersion !== 1) throw new EvidenceError('evidencePolicy.schemaVersion 必须是 1');
  const types = requireObject(policy.types, 'evidencePolicy.types');
  const sources = requireObject(policy.sources, 'evidencePolicy.sources');
  const requirementsBySurface = requireObject(policy.requirementsBySurface, 'evidencePolicy.requirementsBySurface');
  for (const [type, label] of Object.entries(types)) requireText(label, `evidencePolicy.types.${type}`);
  const passingStatuses = requireTextArray(policy.passingStatuses, 'evidencePolicy.passingStatuses', { nonEmpty: true });
  if (passingStatuses.length !== 1 || passingStatuses[0] !== 'passed') {
    throw new EvidenceError('evidencePolicy.passingStatuses 只能是 ["passed"]');
  }
  if (!Array.isArray(policy.checkClassifiers)) throw new EvidenceError('evidencePolicy.checkClassifiers 必须是数组');
  if (!Array.isArray(policy.surfaceClassifiers)) throw new EvidenceError('evidencePolicy.surfaceClassifiers 必须是数组');
  if (!Array.isArray(policy.trustedCheckProducers)) throw new EvidenceError('evidencePolicy.trustedCheckProducers 必须是数组');
  if (!Array.isArray(policy.excludedCheckNames)) throw new EvidenceError('evidencePolicy.excludedCheckNames 必须是数组');
  const codeScanning = requireObject(policy.codeScanning, 'evidencePolicy.codeScanning');
  requireTextArray(codeScanning.trustedTools, 'evidencePolicy.codeScanning.trustedTools', { nonEmpty: true });
  if (!Number.isInteger(codeScanning.minimumRules) || codeScanning.minimumRules < 1) {
    throw new EvidenceError('evidencePolicy.codeScanning.minimumRules 必须是正整数');
  }
  if (!Array.isArray(codeScanning.controlPathPatterns) || codeScanning.controlPathPatterns.length === 0) {
    throw new EvidenceError('evidencePolicy.codeScanning.controlPathPatterns 必须是非空数组');
  }
  codeScanning.controlPathPatterns.forEach((pattern, index) => {
    requireRegex(pattern, `evidencePolicy.codeScanning.controlPathPatterns[${index}]`);
  });
  for (const [source, config] of Object.entries(sources)) {
    requireObject(config, `evidencePolicy.sources.${source}`);
    if (typeof config.verified !== 'boolean') {
      throw new EvidenceError(`evidencePolicy.sources.${source} 配置无效`);
    }
    requireTextArray(config.allowedStatuses, `evidencePolicy.sources.${source}.allowedStatuses`, { nonEmpty: true });
    const allowedTypes = requireTextArray(config.allowedTypes, `evidencePolicy.sources.${source}.allowedTypes`, { nonEmpty: true });
    for (const type of allowedTypes) {
      if (!hasOwn(types, type)) throw new EvidenceError(`${source} 引用了未知证据类型 ${type}`);
    }
  }
  for (const source of ['pr_assertion', 'commit_status']) {
    if (!hasOwn(sources, source) || sources[source].verified !== false) {
      throw new EvidenceError(`evidencePolicy.sources.${source}.verified 必须是 false`);
    }
  }
  for (const [surface, requirement] of Object.entries(requirementsBySurface)) {
    requireObject(requirement, `evidencePolicy.requirementsBySurface.${surface}`);
    if (!['block', 'architecture_gate', 'audit'].includes(requirement.enforcement) || !Array.isArray(requirement.anyOf)) {
      throw new EvidenceError(`evidencePolicy.requirementsBySurface.${surface} 配置无效`);
    }
    if (['block', 'architecture_gate'].includes(requirement.enforcement) && requirement.anyOf.length === 0) {
      throw new EvidenceError(`evidencePolicy.requirementsBySurface.${surface}.anyOf 不能为空`);
    }
    for (const type of requirement.anyOf) {
      if (!hasOwn(types, type)) throw new EvidenceError(`${surface} 引用了未知证据类型 ${type}`);
    }
  }
  for (const [index, classifier] of policy.checkClassifiers.entries()) {
    requireObject(classifier, `evidencePolicy.checkClassifiers[${index}]`);
    const type = requireText(classifier.type, `evidencePolicy.checkClassifiers[${index}].type`);
    if (!hasOwn(types, type)) throw new EvidenceError(`checkClassifiers[${index}] 引用了未知证据类型 ${type}`);
    requireRegex(classifier.pattern, `evidencePolicy.checkClassifiers[${index}].pattern`);
  }
  for (const [index, classifier] of policy.surfaceClassifiers.entries()) {
    requireObject(classifier, `evidencePolicy.surfaceClassifiers[${index}]`);
    requireText(classifier.id, `evidencePolicy.surfaceClassifiers[${index}].id`);
    const surface = requireText(classifier.surface, `evidencePolicy.surfaceClassifiers[${index}].surface`);
    if (!hasOwn(requirementsBySurface, surface)) {
      throw new EvidenceError(`surfaceClassifiers[${index}] 引用了未知敏感面 ${surface}`);
    }
    requireRegex(classifier.pathPattern, `evidencePolicy.surfaceClassifiers[${index}].pathPattern`);
  }
  requireTextArray(policy.trustedCheckProducers, 'evidencePolicy.trustedCheckProducers');
  requireTextArray(policy.excludedCheckNames, 'evidencePolicy.excludedCheckNames');
  return policy;
}

export function normalizeEvidenceRecord(raw, { candidateSha, policy, label = 'evidence' }) {
  const source = requireObject(raw, label);
  const type = requireText(source.type, `${label}.type`);
  const origin = requireText(source.source, `${label}.source`);
  const status = requireText(source.status, `${label}.status`);
  const sha = requireText(source.sha, `${label}.sha`);
  if (!hasOwn(policy.types, type)) throw new EvidenceError(`${label}.type 不在机器策略中`);
  if (!hasOwn(policy.sources, origin)) throw new EvidenceError(`${label}.source 不在机器策略中`);
  const sourcePolicy = policy.sources[origin];
  if (!sourcePolicy.allowedTypes.includes(type)) throw new EvidenceError(`${label}.type 与 source 不匹配`);
  if (!sourcePolicy.allowedStatuses.includes(status)) throw new EvidenceError(`${label}.status 与 source 不匹配`);
  if (sha !== candidateSha) throw new EvidenceError(`${label}.sha 未绑定当前候选 SHA`);
  const producer = source.producer === undefined || source.producer === null || source.producer === ''
    ? undefined
    : requireText(source.producer, `${label}.producer`);
  const record = {
    type,
    source: origin,
    status,
    sha,
    url: requireHttpsUrl(source.url, `${label}.url`),
    name: requireText(source.name, `${label}.name`).slice(0, 300),
    summary: requireText(source.summary, `${label}.summary`).slice(0, 2_000),
    ...(producer ? { producer } : {}),
  };
  const trustedProducer = origin !== 'github_check' || (producer && policy.trustedCheckProducers.includes(producer));
  record.verified = Boolean(sourcePolicy.verified && trustedProducer && policy.passingStatuses.includes(status));
  record.id = evidenceId(record);
  if (source.id !== undefined && source.id !== record.id) throw new EvidenceError(`${label}.id 与证据内容不匹配`);
  if (source.verified !== undefined && source.verified !== record.verified) {
    throw new EvidenceError(`${label}.verified 不能覆盖机器判定`);
  }
  return record;
}

export function normalizeEvidenceCatalog(items, { candidateSha, policy, label = 'evidence' }) {
  if (!Array.isArray(items)) throw new EvidenceError(`${label} 必须是数组`);
  const byId = new Map();
  items.forEach((item, index) => {
    const normalized = normalizeEvidenceRecord(item, { candidateSha, policy, label: `${label}[${index}]` });
    byId.set(normalized.id, normalized);
  });
  return [...byId.values()];
}

export function validateModelEvidence(items, catalog, { candidateSha, policy }) {
  const selected = normalizeEvidenceCatalog(items, { candidateSha, policy, label: 'evidence' });
  const available = new Map(catalog.map(item => [item.id, item]));
  for (const item of selected) {
    if (!available.has(item.id)) throw new EvidenceError(`evidence ${item.id} 不在门禁采集的证据目录中`);
  }
  return selected.map(item => available.get(item.id));
}

export function classifyCheckName(name, policy) {
  for (const classifier of policy.checkClassifiers) {
    if (new RegExp(classifier.pattern, 'i').test(name)) return classifier.type;
  }
  return 'ci_check';
}

export function enforceMinimumSurfaces(sensitiveSurfaces, changedFiles, policy) {
  const result = Object.fromEntries(
    Object.entries(sensitiveSurfaces).map(([surface, value]) => [surface, { ...value }]),
  );
  if (!Array.isArray(changedFiles)) throw new EvidenceError('changedFiles 必须是数组');
  for (const classifier of policy.surfaceClassifiers) {
    const pattern = new RegExp(classifier.pathPattern, 'i');
    const matchedPath = changedFiles.find(path => typeof path === 'string' && pattern.test(path.replaceAll('\\', '/')));
    if (matchedPath && result[classifier.surface]?.status === '未涉及') {
      result[classifier.surface] = {
        status: '涉及',
        reason: `机器策略 ${classifier.id} 命中变更路径 ${matchedPath.slice(0, 300)}；模型不得降级。`,
      };
    }
  }
  return result;
}

export function checkStatus(status, conclusion) {
  if (status !== 'completed') return 'pending';
  if (conclusion === 'success') return 'passed';
  if (conclusion === 'neutral') return 'neutral';
  if (conclusion === 'skipped') return 'skipped';
  return 'failed';
}

export function evaluateEvidenceRequirements(sensitiveSurfaces, catalog, policy) {
  const gaps = [];
  for (const [surface, requirement] of Object.entries(policy.requirementsBySurface)) {
    const status = sensitiveSurfaces[surface]?.status;
    if (!['涉及', '无法判断'].includes(status) || requirement.enforcement !== 'block' || requirement.anyOf.length === 0) continue;
    const satisfied = catalog.some(item => item.verified && requirement.anyOf.includes(item.type));
    if (!satisfied) {
      gaps.push({ surface, anyOf: [...requirement.anyOf], enforcement: requirement.enforcement });
    }
  }
  return gaps;
}

export function evidenceTypeLabel(type, policy) {
  return policy.types[type] ?? type;
}
