const express = require("express");
const MicroShield = require("./index");
const createTelemetryStore = require("./lib/telemetryStore");
const createPolicyEngine = require("./lib/policyEngine");
const axios = require("axios");
const fs = require("fs");
const path = require("path");

const app = express();
const benchmarkMode = process.env.BENCHMARK_MODE === "1";
const PORT = Number(process.env.PORT || 3012);
const aiUrl = process.env.AI_URL || "http://127.0.0.1:8001/predict";
const adminToken = String(process.env.OBSERVABILITY_ADMIN_TOKEN || "").trim();
const defaultTenantId = String(process.env.DEFAULT_TENANT_ID || "public").trim() || "public";
const requireTenantId = process.env.REQUIRE_TENANT_ID === "1";
const siblingVulnerableDb = path.join(
  __dirname,
  "..",
  "microshield-ai-engine",
  "demo-vulnerable-app",
  "data",
  "microshield_events.sqlite"
);
const defaultTelemetryDb = process.env.TELEMETRY_DB || (fs.existsSync(siblingVulnerableDb) ? siblingVulnerableDb : "");
const telemetryStore = createTelemetryStore({
  dbPath: defaultTelemetryDb,
});
const policyEngine = createPolicyEngine();

telemetryStore.init().catch(() => {});

async function loadPersistedPolicies() {
  try {
    const persisted = await telemetryStore.loadPolicies();
    if (persisted && (persisted.defaultPolicy || (persisted.routes && persisted.routes.length))) {
      policyEngine.importSnapshot(persisted);
    }
  } catch {
    // Policy loading should not crash boot.
  }
}

loadPersistedPolicies().catch(() => {});

function getProvidedAdminToken(req) {
  const headerToken = String(req.headers["x-admin-token"] || "").trim();
  if (headerToken) return headerToken;

  const authHeader = String(req.headers.authorization || "").trim();
  if (authHeader.toLowerCase().startsWith("bearer ")) {
    return authHeader.slice(7).trim();
  }

  return "";
}

function requireAdmin(req, res, next) {
  if (!adminToken) return next();
  const provided = getProvidedAdminToken(req);
  if (provided && provided === adminToken) return next();
  return res.status(401).json({ error: "Unauthorized admin action" });
}

function resolveTenantId(req) {
  const tenant = String(
    req.headers["x-tenant-id"] || req.query.tenantId || req.body?.tenantId || defaultTenantId
  ).trim();
  return tenant || defaultTenantId;
}

function resolveUserId(req) {
  const user = String(req.headers["x-user-id"] || req.query.userId || req.body?.userId || "anonymous").trim();
  return user || "anonymous";
}

const middlewareOptions = {
  aiUrl,
  mode: "protect",
  failOpen: true,
  sampleRate: 1,
  telemetryStore,
  policyEngine,
};

if (benchmarkMode) {
  middlewareOptions.rateLimit = { windowMs: 60_000, max: 10_000 };
}

/* ---------- MIDDLEWARE ---------- */
app.use(express.json());
app.use((req, res, next) => {
  req._tenantId = resolveTenantId(req);
  req._userId = resolveUserId(req);
  if (requireTenantId && !String(req.headers["x-tenant-id"] || "").trim()) {
    return res.status(400).json({ error: "x-tenant-id header required" });
  }
  return next();
});
const shieldMiddleware = MicroShield(middlewareOptions);
app.use((req, res, next) => {
  if (String(req.path || "").startsWith("/observability")) return next();
  return shieldMiddleware(req, res, next);
});


/* ---------- ROUTES ---------- */
app.post("/login", (req, res) => {
  res.json({ message: "Login successful" });
});

app.get("/", (req, res) => {
  res.send("MicroShield Test App Running");
});

app.get("/observability/events", async (req, res) => {
  try {
    const limit = Number(req.query.limit || 100);
    const offset = Number(req.query.offset || 0);
    const events = await telemetryStore.listEvents(limit, {
      tenantId: req._tenantId,
      userId: req.query.userId,
      source: req.query.source,
      route: req.query.route,
      method: req.query.method,
      ip: req.query.ip,
      risk: req.query.risk,
      ruleId: req.query.ruleId,
      blocked: req.query.blocked,
      statusCode: req.query.statusCode,
      from: req.query.from,
      to: req.query.to,
    }, offset);

    const items = (events.items || []).map((row) => {
      const tenantId = row.tenant_id || row.tenantId || defaultTenantId;
      const userId = row.user_id || row.userId || "anonymous";
      return Object.assign({}, row, {
        tenant_id: tenantId,
        user_id: userId,
        tenantId,
        userId,
      });
    });

    res.json({
      items,
      paging: {
        total: events.total,
        limit,
        offset,
      },
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.get("/observability/metrics", async (req, res) => {
  try {
    const metrics = await telemetryStore.getMetrics(Number(req.query.windowMinutes || 60), {
      tenantId: req._tenantId,
    });
    res.json(Object.assign({ tenantId: req._tenantId }, metrics));
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.post("/observability/false-positive", requireAdmin, async (req, res) => {
  try {
    const eventId = Number(req.body?.eventId || 0);
    if (!eventId) return res.status(400).json({ error: "eventId required" });
    await telemetryStore.markFalsePositive(eventId, String(req.body?.note || ""));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.get("/observability/false-positive/queue", async (req, res) => {
  try {
    const limit = Number(req.query.limit || 100);
    const offset = Number(req.query.offset || 0);
    const queue = await telemetryStore.listFalsePositiveQueue(limit, {
      tenantId: req._tenantId,
      userId: req.query.userId,
      source: req.query.source,
      route: req.query.route,
      ruleId: req.query.ruleId,
      risk: req.query.risk,
      from: req.query.from,
      to: req.query.to,
    }, offset);

    const items = (queue.items || []).map((row) => {
      const tenantId = row.tenant_id || row.tenantId || defaultTenantId;
      const userId = row.user_id || row.userId || "anonymous";
      return Object.assign({}, row, {
        tenant_id: tenantId,
        user_id: userId,
        tenantId,
        userId,
      });
    });

    res.json({
      items,
      paging: {
        total: queue.total,
        limit,
        offset,
      },
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.get("/observability/blocklist", async (_req, res) => {
  try {
    const blocked = await telemetryStore.listBlockedIps();
    res.json({ items: blocked });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.post("/observability/blocklist", requireAdmin, async (req, res) => {
  try {
    const ip = String(req.body?.ip || "").trim();
    if (!ip) return res.status(400).json({ error: "ip required" });
    await telemetryStore.blockIp(ip, String(req.body?.reason || "manual"));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.delete("/observability/blocklist", requireAdmin, async (req, res) => {
  try {
    const ip = String(req.body?.ip || "").trim();
    if (!ip) return res.status(400).json({ error: "ip required" });
    await telemetryStore.unblockIp(ip);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.get("/observability/health", async (_req, res) => {
  try {
    let aiUp = false;
    try {
      await axios.post(aiUrl, {
        pathLength: 1,
        bodySize: 1,
        queryParams: 0,
        specialChars: 0,
        entropy: 0,
        methodPOST: 0,
      }, { timeout: 1500 });
      aiUp = true;
    } catch {
      aiUp = false;
    }

    await telemetryStore.recordHealth({ aiUp, aiTimeoutRate: 0, queueDepth: 0, metadata: {} });
    res.json({ aiUp, aiUrl, benchmarkMode });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.get("/observability/policies", (_req, res) => {
  try {
    res.json(policyEngine.getSnapshot());
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.put("/observability/policies/default", requireAdmin, async (req, res) => {
  try {
    const actor = String(req.body?.actor || "api");
    const updated = policyEngine.setDefaultPolicy(req.body || {});
    await telemetryStore.saveDefaultPolicy(updated, actor);
    res.json({ ok: true, defaultPolicy: updated });
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) });
  }
});

app.put("/observability/policies/route", requireAdmin, async (req, res) => {
  try {
    const pattern = String(req.body?.pattern || "").trim();
    const method = String(req.body?.method || "*").trim();
    const actor = String(req.body?.actor || "api");
    if (!pattern) return res.status(400).json({ error: "pattern required" });
    const entry = policyEngine.upsertRoutePolicy(pattern, method, req.body?.policy || {});
    await telemetryStore.upsertRoutePolicy(entry.pattern, entry.method, entry.policy, actor);
    res.json({ ok: true, routePolicy: entry });
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) });
  }
});

app.delete("/observability/policies/route", requireAdmin, async (req, res) => {
  try {
    const pattern = String(req.body?.pattern || "").trim();
    const method = String(req.body?.method || "*").trim();
    const actor = String(req.body?.actor || "api");
    if (!pattern) return res.status(400).json({ error: "pattern required" });
    const removed = policyEngine.removeRoutePolicy(pattern, method);
    await telemetryStore.deleteRoutePolicy(pattern, method, actor);
    res.json({ ok: true, removed });
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) });
  }
});

app.post("/observability/policies/profile", requireAdmin, async (req, res) => {
  try {
    const profile = String(req.body?.profile || "").trim().toLowerCase();
    const actor = String(req.body?.actor || "api");
    if (!profile) return res.status(400).json({ error: "profile required" });
    const target = {
      pattern: req.body?.pattern,
      method: req.body?.method,
    };
    const result = policyEngine.applyProfile(profile, target);
    if (target.pattern) {
      await telemetryStore.upsertRoutePolicy(result.pattern, result.method, result.policy, actor);
    } else {
      await telemetryStore.saveDefaultPolicy(result, actor);
    }
    res.json({ ok: true, applied: result });
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) });
  }
});

app.get("/observability/policies/audit", async (req, res) => {
  try {
    const limit = Number(req.query.limit || 100);
    const offset = Number(req.query.offset || 0);
    const result = await telemetryStore.listPolicyAudit(limit, {
      actor: req.query.actor,
      action: req.query.action,
      targetType: req.query.targetType,
      targetKey: req.query.targetKey,
      from: req.query.from,
      to: req.query.to,
    }, offset);
    res.json({
      items: result.items,
      paging: {
        total: result.total,
        limit,
        offset,
      },
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

/* ---------- SERVER ---------- */
app.listen(PORT, () => {
  console.log(`Test app running on http://localhost:${PORT}`);
  console.log(`AI URL: ${aiUrl}`);
  console.log(`Benchmark mode: ${benchmarkMode}`);
});
