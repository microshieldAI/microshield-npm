function toUpper(v) {
  return String(v || "*").trim().toUpperCase() || "*";
}

function normalizePath(path) {
  const p = String(path || "/").trim();
  if (!p) return "/";
  return p.startsWith("/") ? p : `/${p}`;
}

function toInt(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

const profileTemplates = {
  strict: {
    enableStaticRules: true,
    enableBehaviorGate: true,
    enableAI: true,
    failOpen: false,
    aiBlockRisks: ["medium", "high"],
    rateLimit: { windowMs: 60_000, max: 80 },
    botThresholds: { ipReqPerMin: 70, routeReqPerMin: 45, uniquePathsPerMin: 20 },
  },
  balanced: {
    enableStaticRules: true,
    enableBehaviorGate: true,
    enableAI: true,
    failOpen: true,
    aiBlockRisks: ["medium", "high"],
    rateLimit: { windowMs: 60_000, max: 120 },
    botThresholds: { ipReqPerMin: 90, routeReqPerMin: 60, uniquePathsPerMin: 30 },
  },
  lenient: {
    enableStaticRules: true,
    enableBehaviorGate: false,
    enableAI: true,
    failOpen: true,
    aiBlockRisks: ["high"],
    rateLimit: { windowMs: 60_000, max: 250 },
    botThresholds: { ipReqPerMin: 140, routeReqPerMin: 100, uniquePathsPerMin: 50 },
  },
};

function sanitizePolicyPatch(input) {
  const policy = input || {};
  const out = {};

  if (Object.prototype.hasOwnProperty.call(policy, "enableStaticRules")) {
    out.enableStaticRules = Boolean(policy.enableStaticRules);
  }
  if (Object.prototype.hasOwnProperty.call(policy, "enableBehaviorGate")) {
    out.enableBehaviorGate = Boolean(policy.enableBehaviorGate);
  }
  if (Object.prototype.hasOwnProperty.call(policy, "enableAI")) {
    out.enableAI = Boolean(policy.enableAI);
  }
  if (Object.prototype.hasOwnProperty.call(policy, "failOpen")) {
    out.failOpen = Boolean(policy.failOpen);
  }

  if (Array.isArray(policy.aiBlockRisks)) {
    const risks = policy.aiBlockRisks
      .map((r) => String(r || "").trim().toLowerCase())
      .filter((r) => r === "low" || r === "medium" || r === "high");
    out.aiBlockRisks = Array.from(new Set(risks));
  }

  if (policy.rateLimit && typeof policy.rateLimit === "object") {
    out.rateLimit = {
      windowMs: Math.max(1000, toInt(policy.rateLimit.windowMs, 60_000)),
      max: Math.max(0, toInt(policy.rateLimit.max, 120)),
    };
  }

  if (policy.botThresholds && typeof policy.botThresholds === "object") {
    out.botThresholds = {
      ipReqPerMin: Math.max(1, toInt(policy.botThresholds.ipReqPerMin, 90)),
      routeReqPerMin: Math.max(1, toInt(policy.botThresholds.routeReqPerMin, 60)),
      uniquePathsPerMin: Math.max(1, toInt(policy.botThresholds.uniquePathsPerMin, 30)),
    };
  }

  return out;
}

function mergePolicy(basePolicy, patch) {
  const merged = deepClone(basePolicy);
  const cleanPatch = sanitizePolicyPatch(patch);

  Object.assign(merged, cleanPatch);
  if (cleanPatch.rateLimit) {
    merged.rateLimit = Object.assign({}, basePolicy.rateLimit, cleanPatch.rateLimit);
  }
  if (cleanPatch.botThresholds) {
    merged.botThresholds = Object.assign({}, basePolicy.botThresholds, cleanPatch.botThresholds);
  }

  return merged;
}

function routeMatches(routePolicy, reqPath, reqMethod) {
  const methodOk = routePolicy.method === "*" || routePolicy.method === toUpper(reqMethod);
  if (!methodOk) return false;

  const p = routePolicy.pattern;
  if (p === "*") return true;
  if (p.endsWith("*")) {
    const prefix = p.slice(0, -1);
    return normalizePath(reqPath).startsWith(prefix);
  }
  return normalizePath(reqPath) === p;
}

module.exports = function createPolicyEngine(options = {}) {
  const defaultPolicyBase = options.defaultPolicy || profileTemplates.balanced;
  const state = {
    defaultPolicy: mergePolicy(profileTemplates.balanced, defaultPolicyBase),
    routes: [],
  };

  function getProfiles() {
    return deepClone(profileTemplates);
  }

  function getSnapshot() {
    return {
      defaultPolicy: deepClone(state.defaultPolicy),
      routes: deepClone(state.routes),
      profiles: getProfiles(),
    };
  }

  function setDefaultPolicy(patch) {
    state.defaultPolicy = mergePolicy(state.defaultPolicy, patch);
    return deepClone(state.defaultPolicy);
  }

  function applyProfile(profileName, target = {}) {
    const key = String(profileName || "").trim().toLowerCase();
    const profile = profileTemplates[key];
    if (!profile) {
      throw new Error(`Unknown profile: ${profileName}`);
    }

    if (target.pattern) {
      return upsertRoutePolicy(target.pattern, target.method || "*", profile);
    }

    state.defaultPolicy = mergePolicy(state.defaultPolicy, profile);
    return deepClone(state.defaultPolicy);
  }

  function upsertRoutePolicy(pattern, method = "*", patch = {}) {
    const normalizedPattern = pattern === "*" ? "*" : normalizePath(pattern);
    const normalizedMethod = toUpper(method);
    const idx = state.routes.findIndex((r) => r.pattern === normalizedPattern && r.method === normalizedMethod);
    if (idx >= 0) {
      state.routes[idx].policy = mergePolicy(state.routes[idx].policy, patch);
      return deepClone(state.routes[idx]);
    }

    const entry = {
      pattern: normalizedPattern,
      method: normalizedMethod,
      policy: mergePolicy(state.defaultPolicy, patch),
    };
    state.routes.push(entry);
    return deepClone(entry);
  }

  function removeRoutePolicy(pattern, method = "*") {
    const normalizedPattern = pattern === "*" ? "*" : normalizePath(pattern);
    const normalizedMethod = toUpper(method);
    const before = state.routes.length;
    state.routes = state.routes.filter((r) => !(r.pattern === normalizedPattern && r.method === normalizedMethod));
    return before !== state.routes.length;
  }

  function resolve(req) {
    const reqPath = req.path || req.originalUrl || "/";
    const reqMethod = req.method || "GET";

    let matched = null;
    for (const route of state.routes) {
      if (routeMatches(route, reqPath, reqMethod)) {
        matched = route;
        break;
      }
    }

    const policy = matched ? deepClone(matched.policy) : deepClone(state.defaultPolicy);
    return {
      policy,
      matchedRoute: matched ? { pattern: matched.pattern, method: matched.method } : null,
    };
  }

  function importSnapshot(snapshot = {}) {
    if (snapshot.defaultPolicy && typeof snapshot.defaultPolicy === "object") {
      state.defaultPolicy = mergePolicy(state.defaultPolicy, snapshot.defaultPolicy);
    }
    state.routes = [];
    const routes = Array.isArray(snapshot.routes) ? snapshot.routes : [];
    for (const route of routes) {
      if (!route || !route.pattern) continue;
      upsertRoutePolicy(route.pattern, route.method || "*", route.policy || {});
    }
    return getSnapshot();
  }

  return {
    getSnapshot,
    getProfiles,
    setDefaultPolicy,
    applyProfile,
    upsertRoutePolicy,
    removeRoutePolicy,
    importSnapshot,
    resolve,
  };
};
