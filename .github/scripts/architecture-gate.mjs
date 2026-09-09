import { createHash } from 'node:crypto';

const POLICY_PATHS = ['.pr-security-gate/architecture.json', '.pr-security-gate/debt.json'];

export class ArchitectureGateError extends Error {}

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ArchitectureGateError(`${label} must be an object`);
  }
  return value;
}

function requireText(value, label) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new ArchitectureGateError(`${label} must be non-empty text`);
  }
  return value.trim();
}

function requireTextArray(value, label, { nonEmpty = false } = {}) {
  if (!Array.isArray(value) || (nonEmpty && value.length === 0)) {
    throw new ArchitectureGateError(`${label} must be ${nonEmpty ? 'a non-empty ' : 'an '}array`);
  }
  const result = value.map((item, index) => requireText(item, `${label}[${index}]`));
  if (new Set(result).size !== result.length) {
    throw new ArchitectureGateError(`${label} must not contain duplicates`);
  }
  return result;
}

function requireNonNegativeInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) {
    throw new ArchitectureGateError(`${label} must be a non-negative integer`);
  }
  return value;
}

function normalizePath(value, label = 'path') {
  const path = requireText(value, label).replaceAll('\\', '/').replace(/^\.\//, '');
  const normalized = path.replace(/\/{2,}/g, '/');
  if (normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized)) {
    throw new ArchitectureGateError(`${label} must be a repository-relative path`);
  }
  const segments = normalized.split('/').filter(segment => segment !== '.');
  if (segments.includes('..')) {
    throw new ArchitectureGateError(`${label} must not contain parent traversal`);
  }
  const result = segments.join('/');
  if (result === '') throw new ArchitectureGateError(`${label} must not resolve to an empty path`);
  return result;
}

function normalizeGlob(value, label) {
  return normalizePath(value, label);
}

function globRegExp(glob) {
  let source = '^';
  for (let index = 0; index < glob.length;) {
    const character = glob[index];
    if (character === '*' && glob[index + 1] === '*') {
      if (glob[index + 2] === '/') {
        source += '(?:.*/)?';
        index += 3;
      } else {
        source += '.*';
        index += 2;
      }
    } else if (character === '*') {
      source += '[^/]*';
      index += 1;
    } else if (character === '?') {
      source += '[^/]';
      index += 1;
    } else {
      source += character.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
      index += 1;
    }
  }
  return new RegExp(`${source}$`);
}

export function matchesGlob(path, glob) {
  return globRegExp(normalizeGlob(glob, 'glob')).test(normalizePath(path));
}

export function validateArchitectureContract(raw) {
  const source = requireObject(raw, 'architecture contract');
  if (source.version !== 1) {
    throw new ArchitectureGateError('architecture contract version must be 1');
  }
  const contractChangeCheck = requireText(source.contractChangeCheck, 'contractChangeCheck');
  if (!Array.isArray(source.components) || source.components.length === 0) {
    throw new ArchitectureGateError('components must be a non-empty array');
  }

  const components = source.components.map((rawComponent, index) => {
    const component = requireObject(rawComponent, `components[${index}]`);
    return {
      name: requireText(component.name, `components[${index}].name`),
      paths: requireTextArray(component.paths, `components[${index}].paths`, { nonEmpty: true })
        .map((path, pathIndex) => normalizeGlob(path, `components[${index}].paths[${pathIndex}]`)),
      referenceMarkers: requireTextArray(component.referenceMarkers, `components[${index}].referenceMarkers`),
      allowedDependencies: requireTextArray(component.allowedDependencies, `components[${index}].allowedDependencies`),
    };
  });
  const componentNames = new Set(components.map(component => component.name));
  if (componentNames.size !== components.length) {
    throw new ArchitectureGateError('component names must be unique');
  }
  const allMarkers = components.flatMap(component => component.referenceMarkers);
  if (new Set(allMarkers).size !== allMarkers.length) {
    throw new ArchitectureGateError('component referenceMarkers must be globally unique');
  }
  for (const component of components) {
    for (const dependency of component.allowedDependencies) {
      if (!componentNames.has(dependency)) {
        throw new ArchitectureGateError(`${component.name} allows unknown dependency ${dependency}`);
      }
      if (dependency === component.name) {
        throw new ArchitectureGateError(`${component.name} must not list itself as a dependency`);
      }
    }
  }

  if (!Array.isArray(source.resourceRules)) {
    throw new ArchitectureGateError('resourceRules must be an array');
  }
  const resourceRules = source.resourceRules.map((rawRule, index) => {
    const rule = requireObject(rawRule, `resourceRules[${index}]`);
    const allowedComponents = requireTextArray(
      rule.allowedComponents,
      `resourceRules[${index}].allowedComponents`,
      { nonEmpty: true },
    );
    for (const component of allowedComponents) {
      if (!componentNames.has(component)) {
        throw new ArchitectureGateError(`resourceRules[${index}] allows unknown component ${component}`);
      }
    }
    return {
      id: requireText(rule.id, `resourceRules[${index}].id`),
      referenceMarkers: requireTextArray(
        rule.referenceMarkers,
        `resourceRules[${index}].referenceMarkers`,
        { nonEmpty: true },
      ),
      allowedComponents,
    };
  });
  if (new Set(resourceRules.map(rule => rule.id)).size !== resourceRules.length) {
    throw new ArchitectureGateError('resource rule ids must be unique');
  }

  const rawCombinationRules = source.combinationRules ?? [];
  if (!Array.isArray(rawCombinationRules)) {
    throw new ArchitectureGateError('combinationRules must be an array');
  }
  const combinationRules = rawCombinationRules.map((rawRule, index) => {
    const rule = requireObject(rawRule, `combinationRules[${index}]`);
    const scope = rule.scope === undefined ? 'repository' : requireText(rule.scope, `combinationRules[${index}].scope`);
    if (!['repository', 'component'].includes(scope)) {
      throw new ArchitectureGateError(`combinationRules[${index}].scope must be repository or component`);
    }
    const components = rule.components === undefined
      ? [...componentNames]
      : requireTextArray(rule.components, `combinationRules[${index}].components`, { nonEmpty: true });
    for (const component of components) {
      if (!componentNames.has(component)) {
        throw new ArchitectureGateError(`combinationRules[${index}] contains unknown component ${component}`);
      }
    }
    return {
      id: requireText(rule.id, `combinationRules[${index}].id`),
      sourceMarkers: requireTextArray(
        rule.sourceMarkers,
        `combinationRules[${index}].sourceMarkers`,
        { nonEmpty: true },
      ),
      sinkMarkers: requireTextArray(
        rule.sinkMarkers,
        `combinationRules[${index}].sinkMarkers`,
        { nonEmpty: true },
      ),
      scope,
      components,
    };
  });
  if (new Set(combinationRules.map(rule => rule.id)).size !== combinationRules.length) {
    throw new ArchitectureGateError('combination rule ids must be unique');
  }

  if (!Array.isArray(source.criticalPaths)) {
    throw new ArchitectureGateError('criticalPaths must be an array');
  }
  const criticalPaths = source.criticalPaths.map((rawRule, index) => {
    const rule = requireObject(rawRule, `criticalPaths[${index}]`);
    return {
      id: requireText(rule.id, `criticalPaths[${index}].id`),
      paths: requireTextArray(rule.paths, `criticalPaths[${index}].paths`, { nonEmpty: true })
        .map((path, pathIndex) => normalizeGlob(path, `criticalPaths[${index}].paths[${pathIndex}]`)),
      requiredChecks: requireTextArray(
        rule.requiredChecks,
        `criticalPaths[${index}].requiredChecks`,
        { nonEmpty: true },
      ),
    };
  });
  if (new Set(criticalPaths.map(rule => rule.id)).size !== criticalPaths.length) {
    throw new ArchitectureGateError('critical path ids must be unique');
  }

  const rawBudgets = requireObject(source.debtBudgets, 'debtBudgets');
  const debtMode = requireText(rawBudgets.mode, 'debtBudgets.mode');
  if (!['ratchet', 'budget'].includes(debtMode)) {
    throw new ArchitectureGateError('debtBudgets.mode must be ratchet or budget');
  }
  const rawComponentBudgets = requireObject(rawBudgets.components, 'debtBudgets.components');
  const componentBudgets = {};
  for (const [name, value] of Object.entries(rawComponentBudgets)) {
    if (!componentNames.has(name)) {
      throw new ArchitectureGateError(`debtBudgets.components contains unknown component ${name}`);
    }
    componentBudgets[name] = requireNonNegativeInteger(value, `debtBudgets.components.${name}`);
  }
  for (const name of componentNames) {
    if (!Object.hasOwn(componentBudgets, name)) {
      throw new ArchitectureGateError(`debtBudgets.components is missing component ${name}`);
    }
  }

  return {
    version: 1,
    contractChangeCheck,
    components,
    resourceRules,
    combinationRules,
    criticalPaths,
    debtBudgets: {
      mode: debtMode,
      total: requireNonNegativeInteger(rawBudgets.total, 'debtBudgets.total'),
      components: componentBudgets,
      maxAgeDays: rawBudgets.maxAgeDays === undefined || rawBudgets.maxAgeDays === null
        ? null
        : requireNonNegativeInteger(rawBudgets.maxAgeDays, 'debtBudgets.maxAgeDays'),
    },
  };
}

export function collectRelevantPaths(paths, rawContract) {
  if (!Array.isArray(paths)) {
    throw new ArchitectureGateError('paths must be an array');
  }
  const contract = validateArchitectureContract(rawContract);
  const patterns = [
    ...contract.components.flatMap(component => component.paths),
    ...contract.criticalPaths.flatMap(rule => rule.paths),
    ...POLICY_PATHS,
  ];
  return [...new Set(paths.map((path, index) => normalizePath(path, `paths[${index}]`)))]
    .filter(path => patterns.some(pattern => matchesGlob(path, pattern)))
    .sort();
}

function normalizeSnapshot(rawFiles, label) {
  if (!Array.isArray(rawFiles)) {
    throw new ArchitectureGateError(`${label} must be an array`);
  }
  const files = rawFiles.map((rawFile, index) => {
    const file = requireObject(rawFile, `${label}[${index}]`);
    if (typeof file.content !== 'string') {
      throw new ArchitectureGateError(`${label}[${index}].content must be text`);
    }
    return { path: normalizePath(file.path, `${label}[${index}].path`), content: file.content };
  });
  if (new Set(files.map(file => file.path)).size !== files.length) {
    throw new ArchitectureGateError(`${label} contains duplicate paths`);
  }
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

function componentForPath(path, components) {
  const owners = components.filter(component => component.paths.some(pattern => matchesGlob(path, pattern)));
  if (owners.length > 1) {
    throw new ArchitectureGateError(`${path} matches multiple components: ${owners.map(item => item.name).join(', ')}`);
  }
  return owners[0];
}

function buildGraph(rawFiles, contract) {
  const files = normalizeSnapshot(rawFiles, 'files');
  const edges = new Map();
  for (const file of files) {
    const source = componentForPath(file.path, contract.components);
    if (!source) continue;
    for (const target of contract.components) {
      if (source.name === target.name) continue;
      if (!target.referenceMarkers.some(marker => file.content.includes(marker))) continue;
      const key = `${source.name}\0${target.name}`;
      const edge = edges.get(key) ?? { from: source.name, to: target.name, paths: [] };
      edge.paths.push(file.path);
      edges.set(key, edge);
    }
  }
  return {
    nodes: contract.components.map(component => component.name).sort(),
    edges: [...edges.values()]
      .map(edge => ({ ...edge, paths: [...new Set(edge.paths)].sort() }))
      .sort((left, right) => `${left.from}\0${left.to}`.localeCompare(`${right.from}\0${right.to}`)),
  };
}

export function buildDependencyGraph(files, rawContract) {
  return buildGraph(files, validateArchitectureContract(rawContract));
}

export function createRiskFingerprint({ ruleId, component, path }) {
  const values = [
    requireText(ruleId, 'ruleId').toLowerCase(),
    requireText(component, 'component').toLowerCase(),
    normalizePath(path, 'path'),
  ];
  return createHash('sha256').update(JSON.stringify(values)).digest('hex');
}

export const fingerprintRisk = createRiskFingerprint;

function makeViolation({ identity, kind, ruleId, component, path, message, details = {} }) {
  return {
    identity,
    fingerprint: createRiskFingerprint({ ruleId, component, path }),
    kind,
    ruleId,
    component,
    path,
    message,
    details,
  };
}

function dependencyViolations(graph, contract) {
  const byName = new Map(contract.components.map(component => [component.name, component]));
  return graph.edges
    .filter(edge => !byName.get(edge.from).allowedDependencies.includes(edge.to))
    .flatMap(edge => edge.paths.map(path => makeViolation({
      identity: `dependency:${edge.from}:${edge.to}:${path}`,
      kind: 'dependency',
      ruleId: 'architecture.allowed-dependencies',
      component: edge.from,
      path,
      message: `${edge.from} must not depend on ${edge.to}`,
      details: { from: edge.from, to: edge.to, paths: edge.paths },
    })));
}

export function findDependencyViolations(graph, rawContract) {
  return dependencyViolations(requireObject(graph, 'graph'), validateArchitectureContract(rawContract));
}

function stronglyConnectedComponents(graph) {
  const adjacency = new Map(graph.nodes.map(node => [node, []]));
  for (const edge of graph.edges) adjacency.get(edge.from).push(edge.to);
  let nextIndex = 0;
  const indexes = new Map();
  const lowLinks = new Map();
  const stack = [];
  const onStack = new Set();
  const components = [];

  function visit(node) {
    indexes.set(node, nextIndex);
    lowLinks.set(node, nextIndex);
    nextIndex += 1;
    stack.push(node);
    onStack.add(node);

    for (const target of adjacency.get(node)) {
      if (!indexes.has(target)) {
        visit(target);
        lowLinks.set(node, Math.min(lowLinks.get(node), lowLinks.get(target)));
      } else if (onStack.has(target)) {
        lowLinks.set(node, Math.min(lowLinks.get(node), indexes.get(target)));
      }
    }

    if (lowLinks.get(node) !== indexes.get(node)) return;
    const component = [];
    while (stack.length > 0) {
      const member = stack.pop();
      onStack.delete(member);
      component.push(member);
      if (member === node) break;
    }
    if (component.length > 1) components.push(component.sort());
  }

  for (const node of graph.nodes) {
    if (!indexes.has(node)) visit(node);
  }
  return components.sort((left, right) => left.join('\0').localeCompare(right.join('\0')));
}

function cycleViolations(graph) {
  return stronglyConnectedComponents(graph).map(components => {
    const componentSet = new Set(components);
    const paths = [...new Set(graph.edges
      .filter(edge => componentSet.has(edge.from) && componentSet.has(edge.to))
      .flatMap(edge => edge.paths))].sort();
    return makeViolation({
      identity: `cycle:${components.join(':')}`,
      kind: 'cycle',
      ruleId: 'architecture.no-cycle',
      component: components.join(','),
      path: paths[0] ?? components.join(','),
      message: `dependency cycle detected among ${components.join(', ')}`,
      details: { components, paths },
    });
  });
}

export function findDependencyCycles(graph) {
  return cycleViolations(requireObject(graph, 'graph'));
}

function reachability(graph) {
  const adjacency = new Map(graph.nodes.map(node => [node, []]));
  for (const edge of graph.edges) adjacency.get(edge.from).push(edge.to);
  return new Map(graph.nodes.map(node => {
    const reached = new Set();
    const pending = [...adjacency.get(node)];
    while (pending.length > 0) {
      const target = pending.pop();
      if (reached.has(target)) continue;
      reached.add(target);
      pending.push(...adjacency.get(target));
    }
    return [node, reached];
  }));
}

function remainsOneCycle(components, reachable) {
  for (let left = 0; left < components.length; left += 1) {
    for (let right = left + 1; right < components.length; right += 1) {
      if (!reachable.get(components[left]).has(components[right])) return false;
      if (!reachable.get(components[right]).has(components[left])) return false;
    }
  }
  return true;
}

function resourceViolations(rawFiles, contract) {
  const files = normalizeSnapshot(rawFiles, 'files');
  const violations = [];
  for (const file of files) {
    for (const rule of contract.resourceRules) {
      if (!rule.referenceMarkers.some(marker => file.content.includes(marker))) continue;
      const owner = componentForPath(file.path, contract.components)?.name ?? 'unowned';
      if (rule.allowedComponents.includes(owner)) continue;
      violations.push(makeViolation({
        identity: `resource:${rule.id}:${owner}:${file.path}`,
        kind: 'resource',
        ruleId: rule.id,
        component: owner,
        path: file.path,
        message: `${rule.id} resource reference is not allowed in ${owner}`,
        details: { allowedComponents: rule.allowedComponents },
      }));
    }
  }
  return violations.sort((left, right) => left.identity.localeCompare(right.identity));
}

export function findResourceViolations(files, rawContract) {
  return resourceViolations(files, validateArchitectureContract(rawContract));
}

function combinationViolations(rawFiles, contract) {
  const files = normalizeSnapshot(rawFiles, 'files').map(file => ({
    ...file,
    component: componentForPath(file.path, contract.components)?.name ?? 'unowned',
  }));
  const violations = [];
  for (const rule of contract.combinationRules) {
    const eligible = files.filter(file => rule.components.includes(file.component));
    const groups = rule.scope === 'component'
      ? [...new Set(eligible.map(file => file.component))].map(component => ({
          name: component,
          files: eligible.filter(file => file.component === component),
        }))
      : [{ name: 'repository', files: eligible }];
    for (const group of groups) {
      const sourcePaths = group.files
        .filter(file => rule.sourceMarkers.some(marker => file.content.includes(marker)))
        .map(file => file.path);
      const sinkPaths = group.files
        .filter(file => rule.sinkMarkers.some(marker => file.content.includes(marker)))
        .map(file => file.path);
      if (sourcePaths.length === 0 || sinkPaths.length === 0) continue;
      violations.push(makeViolation({
        identity: `combination:${rule.id}:${group.name}`,
        kind: 'combination',
        ruleId: rule.id,
        component: group.name,
        path: sourcePaths[0],
        message: `${rule.id} source and sink markers coexist in ${group.name}; manual data-flow evidence is required`,
        details: {
          scope: rule.scope,
          sourcePaths: [...new Set(sourcePaths)].sort(),
          sinkPaths: [...new Set(sinkPaths)].sort(),
          conservativeCooccurrence: true,
        },
      }));
    }
  }
  return violations.sort((left, right) => left.identity.localeCompare(right.identity));
}

export function findCombinationViolations(files, rawContract) {
  return combinationViolations(files, validateArchitectureContract(rawContract));
}

function requiredCheckViolations(changedFiles, passedChecks, contract) {
  if (!Array.isArray(changedFiles)) {
    throw new ArchitectureGateError('changedFiles must be an array');
  }
  const paths = [...new Set(changedFiles.map((path, index) => normalizePath(path, `changedFiles[${index}]`)))].sort();
  const passed = new Set(requireTextArray(passedChecks, 'passedChecks'));
  const violations = [];
  for (const rule of contract.criticalPaths) {
    const affectedPaths = paths.filter(path => rule.paths.some(pattern => matchesGlob(path, pattern)));
    if (affectedPaths.length === 0) continue;
    for (const check of rule.requiredChecks) {
      if (passed.has(check)) continue;
      violations.push(makeViolation({
        identity: `required-check:${rule.id}:${check}`,
        kind: 'required-check',
        ruleId: `critical-path.${rule.id}`,
        component: 'repository',
        path: affectedPaths[0],
        message: `${check} must pass for critical path ${rule.id}`,
        details: { check, affectedPaths },
      }));
    }
  }
  return violations;
}

export function findRequiredCheckViolations(changedFiles, passedChecks, rawContract) {
  return requiredCheckViolations(changedFiles, passedChecks, validateArchitectureContract(rawContract));
}

function normalizeDebtItem(rawItem, label, { requireFingerprint = true, requireFirstSeen = true } = {}) {
  const item = requireObject(rawItem, label);
  const level = requireText(item.level, `${label}.level`);
  if (!['P1', 'P2'].includes(level)) {
    throw new ArchitectureGateError(`${label}.level must be P1 or P2`);
  }
  const normalized = {
    ruleId: requireText(item.ruleId, `${label}.ruleId`),
    component: requireText(item.component, `${label}.component`),
    path: normalizePath(item.path, `${label}.path`),
    level,
  };
  const expectedFingerprint = createRiskFingerprint(normalized);
  if (requireFingerprint || item.fingerprint !== undefined) {
    const suppliedFingerprint = requireText(item.fingerprint, `${label}.fingerprint`).toLowerCase();
    if (suppliedFingerprint !== expectedFingerprint) {
      throw new ArchitectureGateError(`${label}.fingerprint does not match ruleId, component and path`);
    }
  }
  if (requireFirstSeen || item.firstSeen !== undefined) {
    normalized.firstSeen = requireText(item.firstSeen, `${label}.firstSeen`);
    if (Number.isNaN(Date.parse(normalized.firstSeen))) {
      throw new ArchitectureGateError(`${label}.firstSeen must be a date or timestamp`);
    }
  }
  return { fingerprint: expectedFingerprint, ...normalized };
}

export function validateDebtLedger(raw) {
  const source = requireObject(raw, 'debt ledger');
  if (source.version !== 1) {
    throw new ArchitectureGateError('debt ledger version must be 1');
  }
  if (!Array.isArray(source.items)) {
    throw new ArchitectureGateError('debt ledger items must be an array');
  }
  const items = source.items.map((item, index) => normalizeDebtItem(item, `items[${index}]`));
  if (new Set(items.map(item => item.fingerprint)).size !== items.length) {
    throw new ArchitectureGateError('debt ledger fingerprints must be unique');
  }
  return { version: 1, items };
}

function countByComponent(items) {
  const counts = {};
  for (const item of items) counts[item.component] = (counts[item.component] ?? 0) + 1;
  return counts;
}

function debtLimitViolation({ baseCount, candidateCount, limit, component, mode }) {
  const path = '.pr-security-gate/debt.json';
  if (mode === 'ratchet' && candidateCount > baseCount) {
    const scope = component ? `component ${component}` : 'repository';
    return makeViolation({
      identity: `debt-ratchet:${component ?? 'total'}`,
      kind: 'debt',
      ruleId: component ? 'debt.component-ratchet' : 'debt.total-ratchet',
      component: component ?? 'repository',
      path,
      message: `${scope} debt count increased from baseline ${baseCount} to ${candidateCount}`,
      details: { baseCount, candidateCount, limit, mode },
    });
  }
  if (mode === 'budget' && baseCount <= limit && candidateCount > limit) {
    const scope = component ? `component ${component}` : 'repository';
    return makeViolation({
      identity: `debt-budget:${component ?? 'total'}`,
      kind: 'debt',
      ruleId: component ? 'debt.component-budget' : 'debt.total-budget',
      component: component ?? 'repository',
      path,
      message: `${scope} debt count ${candidateCount} exceeds budget ${limit}`,
      details: { baseCount, candidateCount, limit, mode },
    });
  }
  if (mode === 'budget' && baseCount > limit && candidateCount > baseCount) {
    const scope = component ? `component ${component}` : 'repository';
    return makeViolation({
      identity: `debt-ratchet:${component ?? 'total'}`,
      kind: 'debt',
      ruleId: component ? 'debt.component-ratchet' : 'debt.total-ratchet',
      component: component ?? 'repository',
      path,
      message: `${scope} debt count increased from legacy baseline ${baseCount} to ${candidateCount}`,
      details: { baseCount, candidateCount, limit, mode },
    });
  }
  return undefined;
}

export function evaluateDebtRatchet({
  baseLedger,
  candidateLedger,
  budgets,
  currentItems = [],
  componentNames,
  asOf = new Date(),
}) {
  const base = validateDebtLedger(baseLedger);
  const candidate = validateDebtLedger(candidateLedger);
  const budgetSource = requireObject(budgets, 'budgets');
  const mode = requireText(budgetSource.mode, 'budgets.mode');
  if (!['ratchet', 'budget'].includes(mode)) {
    throw new ArchitectureGateError('budgets.mode must be ratchet or budget');
  }
  const totalBudget = requireNonNegativeInteger(budgetSource.total, 'budgets.total');
  const componentBudgets = requireObject(budgetSource.components, 'budgets.components');
  const maxAgeDays = budgetSource.maxAgeDays === undefined || budgetSource.maxAgeDays === null
    ? null
    : requireNonNegativeInteger(budgetSource.maxAgeDays, 'budgets.maxAgeDays');
  const asOfMs = asOf instanceof Date ? asOf.getTime() : Date.parse(asOf);
  if (!Number.isFinite(asOfMs)) throw new ArchitectureGateError('asOf must be a valid date or timestamp');
  const knownComponents = componentNames ? new Set(componentNames) : undefined;
  if (knownComponents) {
    for (const item of [...base.items, ...candidate.items]) {
      if (item.component !== 'repository' && !knownComponents.has(item.component)) {
        throw new ArchitectureGateError(`debt item uses unknown component ${item.component}`);
      }
    }
  }

  const current = (() => {
    if (!Array.isArray(currentItems)) throw new ArchitectureGateError('currentItems must be an array');
    return currentItems.map((item, index) => normalizeDebtItem(
      item,
      `currentItems[${index}]`,
      { requireFingerprint: false, requireFirstSeen: false },
    ));
  })();
  if (new Set(current.map(item => item.fingerprint)).size !== current.length) {
    throw new ArchitectureGateError('currentItems fingerprints must be unique');
  }
  if (knownComponents) {
    for (const item of current) {
      if (item.component !== 'repository' && !knownComponents.has(item.component)) {
        throw new ArchitectureGateError(`current debt item uses unknown component ${item.component}`);
      }
    }
  }

  const baseByFingerprint = new Map(base.items.map(item => [item.fingerprint, item]));
  const candidateByFingerprint = new Map(candidate.items.map(item => [item.fingerprint, item]));
  const newItems = candidate.items.filter(item => !baseByFingerprint.has(item.fingerprint));
  const existingItems = candidate.items.filter(item => baseByFingerprint.has(item.fingerprint));
  const resolvedItems = base.items.filter(item => !candidateByFingerprint.has(item.fingerprint));
  const missingCurrentItems = current.filter(item => !candidateByFingerprint.has(item.fingerprint));
  const mismatchedCurrentItems = current.filter(item => {
    const recorded = candidateByFingerprint.get(item.fingerprint);
    return recorded && recorded.level !== item.level;
  });
  const overdueItems = maxAgeDays === null
    ? []
    : candidate.items.filter(item => asOfMs - Date.parse(item.firstSeen) > maxAgeDays * 86_400_000);
  const futureFirstSeenItems = candidate.items.filter(item => Date.parse(item.firstSeen) > asOfMs);
  const baseCounts = countByComponent(base.items);
  const candidateCounts = countByComponent(candidate.items);
  const violations = [];

  const totalViolation = debtLimitViolation({
    baseCount: base.items.length,
    candidateCount: candidate.items.length,
    limit: totalBudget,
    mode,
  });
  if (totalViolation) violations.push(totalViolation);

  for (const [component, rawLimit] of Object.entries(componentBudgets)) {
    if (knownComponents && !knownComponents.has(component)) {
      throw new ArchitectureGateError(`budgets contains unknown component ${component}`);
    }
    const limit = requireNonNegativeInteger(rawLimit, `budgets.components.${component}`);
    const violation = debtLimitViolation({
      baseCount: baseCounts[component] ?? 0,
      candidateCount: candidateCounts[component] ?? 0,
      limit,
      component,
      mode,
    });
    if (violation) violations.push(violation);
  }

  for (const item of existingItems) {
    const baseline = baseByFingerprint.get(item.fingerprint);
    if (item.firstSeen !== baseline.firstSeen) {
      violations.push(makeViolation({
        identity: `debt-first-seen:${item.fingerprint}`,
        kind: 'debt',
        ruleId: 'debt.first-seen-integrity',
        component: item.component,
        path: item.path,
        message: `firstSeen changed for debt item ${item.fingerprint}`,
      }));
    }
    if (item.level !== baseline.level) {
      violations.push(makeViolation({
        identity: `debt-level:${item.fingerprint}`,
        kind: 'debt',
        ruleId: 'debt.level-integrity',
        component: item.component,
        path: item.path,
        message: `level changed from ${baseline.level} to ${item.level} for debt item ${item.fingerprint}`,
      }));
    }
  }
  for (const item of missingCurrentItems) {
    violations.push(makeViolation({
      identity: `debt-missing-current:${item.fingerprint}`,
      kind: 'debt',
      ruleId: 'debt.current-item-recorded',
      component: item.component,
      path: item.path,
      message: `current ${item.level} item is missing from the candidate debt ledger`,
    }));
  }
  for (const item of mismatchedCurrentItems) {
    const recorded = candidateByFingerprint.get(item.fingerprint);
    violations.push(makeViolation({
      identity: `debt-current-level:${item.fingerprint}`,
      kind: 'debt',
      ruleId: 'debt.current-level-match',
      component: item.component,
      path: item.path,
      message: `current ${item.level} item is recorded as ${recorded.level} in the candidate debt ledger`,
    }));
  }
  for (const item of overdueItems) {
    violations.push(makeViolation({
      identity: `debt-overdue:${item.fingerprint}`,
      kind: 'debt',
      ruleId: 'debt.max-age',
      component: item.component,
      path: item.path,
      message: `debt item ${item.fingerprint} is older than ${maxAgeDays} days`,
      details: { firstSeen: item.firstSeen, maxAgeDays, asOf: new Date(asOfMs).toISOString() },
    }));
  }
  for (const item of futureFirstSeenItems) {
    violations.push(makeViolation({
      identity: `debt-first-seen-future:${item.fingerprint}`,
      kind: 'debt',
      ruleId: 'debt.first-seen-future',
      component: item.component,
      path: item.path,
      message: `firstSeen is in the future for debt item ${item.fingerprint}`,
      details: { firstSeen: item.firstSeen, asOf: new Date(asOfMs).toISOString() },
    }));
  }

  return {
    baseCount: base.items.length,
    candidateCount: candidate.items.length,
    mode,
    baseCounts,
    candidateCounts,
    newItems,
    existingItems,
    resolvedItems,
    missingCurrentItems,
    mismatchedCurrentItems,
    overdueItems,
    futureFirstSeenItems,
    violations,
  };
}

function changedPaths(baseFiles, candidateFiles) {
  const base = new Map(baseFiles.map(file => [file.path, file.content]));
  const candidate = new Map(candidateFiles.map(file => [file.path, file.content]));
  return [...new Set([...base.keys(), ...candidate.keys()])]
    .filter(path => base.get(path) !== candidate.get(path))
    .sort();
}

function compareByIdentity(baseViolations, candidateViolations) {
  const base = new Map(baseViolations.map(item => [item.identity, item]));
  const candidate = new Map(candidateViolations.map(item => [item.identity, item]));
  return {
    newViolations: candidateViolations.filter(item => !base.has(item.identity)),
    existingViolations: candidateViolations.filter(item => base.has(item.identity)),
    resolvedViolations: baseViolations.filter(item => !candidate.has(item.identity)),
  };
}

function sortViolations(items) {
  return items.sort((left, right) => left.identity.localeCompare(right.identity));
}

export function evaluateArchitectureGate({
  contract: rawContract,
  baseFiles,
  candidateFiles,
  changedFiles,
  contractChanged = false,
  passedChecks = [],
  baseDebt,
  candidateDebt,
  currentDebtItems = [],
  asOf,
}) {
  if (rawContract === undefined || rawContract === null) {
    return {
      configured: false,
      conclusion: 'BLOCK',
      summary: 'Base architecture contract is required.',
      newViolations: [{
        identity: 'architecture-contract-missing',
        kind: 'architecture',
        ruleId: 'architecture.contract-missing',
        component: 'repository',
        path: '.pr-security-gate/architecture.json',
        message: 'Protected base is missing the required architecture contract.',
        details: {},
      }],
      existingViolations: [],
      resolvedViolations: [],
      debt: {
        mode: null,
        baseCount: 0,
        candidateCount: 0,
        baseCounts: {},
        candidateCounts: {},
        newItems: [],
        existingItems: [],
        resolvedItems: [],
        missingCurrentItems: [],
        violations: [],
      },
    };
  }

  const contract = validateArchitectureContract(rawContract);
  if (typeof contractChanged !== 'boolean') {
    throw new ArchitectureGateError('contractChanged must be a boolean');
  }
  const normalizedBaseFiles = normalizeSnapshot(baseFiles, 'baseFiles');
  const normalizedCandidateFiles = normalizeSnapshot(candidateFiles, 'candidateFiles');
  const actualChangedFiles = changedFiles === undefined
    ? changedPaths(normalizedBaseFiles, normalizedCandidateFiles)
    : changedFiles;
  const baseGraph = buildGraph(normalizedBaseFiles, contract);
  const candidateGraph = buildGraph(normalizedCandidateFiles, contract);

  const comparableBase = [
    ...dependencyViolations(baseGraph, contract),
    ...resourceViolations(normalizedBaseFiles, contract),
    ...combinationViolations(normalizedBaseFiles, contract),
  ];
  const comparableCandidate = [
    ...dependencyViolations(candidateGraph, contract),
    ...resourceViolations(normalizedCandidateFiles, contract),
    ...combinationViolations(normalizedCandidateFiles, contract),
  ];
  const comparable = compareByIdentity(comparableBase, comparableCandidate);

  const baseCycles = cycleViolations(baseGraph);
  const candidateCycles = cycleViolations(candidateGraph);
  const baseReachability = reachability(baseGraph);
  const candidateReachability = reachability(candidateGraph);
  const newCycles = candidateCycles.filter(item => !remainsOneCycle(item.details.components, baseReachability));
  const existingCycles = candidateCycles.filter(item => remainsOneCycle(item.details.components, baseReachability));
  const resolvedCycles = baseCycles.filter(item => !remainsOneCycle(item.details.components, candidateReachability));

  const checkViolations = requiredCheckViolations(actualChangedFiles, passedChecks, contract);
  if (contractChanged && !new Set(passedChecks).has(contract.contractChangeCheck)) {
    checkViolations.push(makeViolation({
      identity: `contract-change-check:${contract.contractChangeCheck}`,
      kind: 'required-check',
      ruleId: 'architecture.contract-change-approval',
      component: 'repository',
      path: '.pr-security-gate/architecture.json',
      message: `${contract.contractChangeCheck} must pass before changing the architecture contract`,
      details: { check: contract.contractChangeCheck },
    }));
  }
  const debt = evaluateDebtRatchet({
    baseLedger: baseDebt,
    candidateLedger: candidateDebt,
    budgets: contract.debtBudgets,
    currentItems: currentDebtItems,
    componentNames: contract.components.map(component => component.name),
    asOf,
  });
  const newViolations = sortViolations([
    ...comparable.newViolations,
    ...newCycles,
    ...checkViolations,
    ...debt.violations,
  ]);
  const existingViolations = sortViolations([...comparable.existingViolations, ...existingCycles]);
  const resolvedViolations = sortViolations([...comparable.resolvedViolations, ...resolvedCycles]);
  const conclusion = newViolations.length > 0 ? 'BLOCK' : 'PASS';

  return {
    configured: true,
    conclusion,
    summary: `架构违规：新增 ${newViolations.length}、已有 ${existingViolations.length}、已消除 ${resolvedViolations.length}；累计债务 ${debt.baseCount} → ${debt.candidateCount}。`,
    newViolations,
    existingViolations,
    resolvedViolations,
    debt,
    baseGraph,
    candidateGraph,
    changedFiles: [...actualChangedFiles],
  };
}
