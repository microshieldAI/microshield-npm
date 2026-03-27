const path = require("path");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();

function run(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) return reject(err);
      return resolve(this);
    });
  });
}

function all(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      return resolve(rows);
    });
  });
}

function get(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      return resolve(row);
    });
  });
}

function toISO(input) {
  if (!input) return new Date().toISOString();
  const d = new Date(input);
  return Number.isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}

function parseJSONSafe(value, fallback) {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function clampLimit(v, fallback = 100) {
  return Math.max(1, Math.min(1000, Number(v) || fallback));
}

function clampOffset(v) {
  return Math.max(0, Number(v) || 0);
}

async function ensureColumn(db, tableName, columnName, definition) {
  const rows = await all(db, `PRAGMA table_info(${tableName})`);
  const exists = rows.some((r) => String(r.name || "").toLowerCase() === String(columnName).toLowerCase());
  if (exists) return;
  await run(db, `ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
}

module.exports = function createTelemetryStore(options = {}) {
  const dbPath = options.dbPath || path.join(process.cwd(), "data", "microshield_events.sqlite");
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new sqlite3.Database(dbPath);

  let initialized = false;

  async function init() {
    if (initialized) return;
    await run(
      db,
      `CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        tenant_id TEXT,
        user_id TEXT,
        trace_id TEXT,
        ip TEXT,
        method TEXT,
        route TEXT,
        source TEXT,
        rule_id TEXT,
        risk TEXT,
        score REAL,
        blocked INTEGER,
        latency_ms REAL,
        status_code INTEGER,
        user_agent TEXT,
        metadata_json TEXT
      )`
    );

    await ensureColumn(db, "security_events", "tenant_id", "TEXT");
    await ensureColumn(db, "security_events", "user_id", "TEXT");

    await run(
      db,
      `CREATE TABLE IF NOT EXISTS blocklist_ips (
        ip TEXT PRIMARY KEY,
        reason TEXT,
        created_at TEXT NOT NULL
      )`
    );

    await run(
      db,
      `CREATE TABLE IF NOT EXISTS false_positive_reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        note TEXT,
        reviewed_at TEXT NOT NULL,
        FOREIGN KEY(event_id) REFERENCES security_events(id)
      )`
    );

    await run(
      db,
      `CREATE TABLE IF NOT EXISTS system_health_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        ai_up INTEGER,
        ai_timeout_rate REAL,
        queue_depth INTEGER,
        metadata_json TEXT
      )`
    );

    await run(
      db,
      `CREATE TABLE IF NOT EXISTS policy_default (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        policy_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT
      )`
    );

    await run(
      db,
      `CREATE TABLE IF NOT EXISTS policy_routes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT NOT NULL,
        method TEXT NOT NULL,
        policy_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT,
        UNIQUE(pattern, method)
      )`
    );

    await run(
      db,
      `CREATE TABLE IF NOT EXISTS policy_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        actor TEXT,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_key TEXT,
        before_json TEXT,
        after_json TEXT,
        metadata_json TEXT
      )`
    );

    initialized = true;
  }

  async function recordEvent(event) {
    await init();
    const e = event || {};
    await run(
      db,
      `INSERT INTO security_events (
        timestamp, tenant_id, user_id, trace_id, ip, method, route, source, rule_id, risk, score,
        blocked, latency_ms, status_code, user_agent, metadata_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        toISO(e.timestamp),
        String(e.tenantId || "public"),
        String(e.userId || "anonymous"),
        e.traceId || "",
        e.ip || "",
        e.method || "",
        e.route || "",
        e.source || "UNKNOWN",
        e.ruleId || "",
        e.risk || "",
        Number.isFinite(Number(e.score)) ? Number(e.score) : null,
        e.blocked ? 1 : 0,
        Number.isFinite(Number(e.latencyMs)) ? Number(e.latencyMs) : null,
        Number.isFinite(Number(e.statusCode)) ? Number(e.statusCode) : null,
        e.userAgent || "",
        JSON.stringify(e.metadata || {}),
      ]
    );
  }

  async function listEvents(limit = 100, filters = {}, offset = 0) {
    await init();
    const params = [];
    const where = [];

    if (filters.source) {
      where.push("source = ?");
      params.push(String(filters.source));
    }
    if (filters.tenantId) {
      where.push("tenant_id = ?");
      params.push(String(filters.tenantId));
    }
    if (filters.userId) {
      where.push("user_id = ?");
      params.push(String(filters.userId));
    }
    if (filters.route) {
      where.push("route = ?");
      params.push(String(filters.route));
    }
    if (filters.method) {
      where.push("method = ?");
      params.push(String(filters.method).toUpperCase());
    }
    if (filters.ip) {
      where.push("ip = ?");
      params.push(String(filters.ip));
    }
    if (filters.risk) {
      where.push("risk = ?");
      params.push(String(filters.risk).toLowerCase());
    }
    if (filters.ruleId) {
      where.push("rule_id = ?");
      params.push(String(filters.ruleId));
    }
    if (filters.blocked !== undefined && filters.blocked !== null && filters.blocked !== "") {
      where.push("blocked = ?");
      params.push(Number(filters.blocked) ? 1 : 0);
    }
    if (filters.statusCode !== undefined && filters.statusCode !== null && filters.statusCode !== "") {
      where.push("status_code = ?");
      params.push(Number(filters.statusCode));
    }
    if (filters.from) {
      where.push("timestamp >= ?");
      params.push(toISO(filters.from));
    }
    if (filters.to) {
      where.push("timestamp <= ?");
      params.push(toISO(filters.to));
    }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const totalRow = await get(
      db,
      `SELECT COUNT(*) AS total FROM security_events ${whereSql}`,
      params
    );

    const queryParams = params.slice();
    queryParams.push(clampLimit(limit, 100));
    queryParams.push(clampOffset(offset));

    const items = await all(
      db,
      `SELECT * FROM security_events ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?`,
      queryParams
    );

    return {
      items,
      total: Number(totalRow?.total || 0),
    };
  }

  async function listFalsePositiveQueue(limit = 100, filters = {}, offset = 0) {
    await init();
    const params = [];
    const where = ["e.blocked = 1", "r.id IS NULL"];

    if (filters.source) {
      where.push("e.source = ?");
      params.push(String(filters.source));
    }
    if (filters.tenantId) {
      where.push("e.tenant_id = ?");
      params.push(String(filters.tenantId));
    }
    if (filters.userId) {
      where.push("e.user_id = ?");
      params.push(String(filters.userId));
    }
    if (filters.route) {
      where.push("e.route = ?");
      params.push(String(filters.route));
    }
    if (filters.ruleId) {
      where.push("e.rule_id = ?");
      params.push(String(filters.ruleId));
    }
    if (filters.risk) {
      where.push("e.risk = ?");
      params.push(String(filters.risk).toLowerCase());
    }
    if (filters.from) {
      where.push("e.timestamp >= ?");
      params.push(toISO(filters.from));
    }
    if (filters.to) {
      where.push("e.timestamp <= ?");
      params.push(toISO(filters.to));
    }

    const whereSql = `WHERE ${where.join(" AND ")}`;
    const totalRow = await get(
      db,
      `SELECT COUNT(*) AS total
       FROM security_events e
       LEFT JOIN false_positive_reviews r ON r.event_id = e.id
       ${whereSql}`,
      params
    );

    const queryParams = params.slice();
    queryParams.push(clampLimit(limit, 100));
    queryParams.push(clampOffset(offset));

    const items = await all(
      db,
      `SELECT e.id, e.timestamp, e.tenant_id, e.user_id, e.ip, e.method, e.route, e.source, e.rule_id, e.risk, e.score, e.status_code
       FROM security_events e
       LEFT JOIN false_positive_reviews r ON r.event_id = e.id
       ${whereSql}
       ORDER BY e.id DESC
       LIMIT ? OFFSET ?`,
      queryParams
    );

    return {
      items,
      total: Number(totalRow?.total || 0),
    };
  }

  async function getMetrics(windowMinutes = 60, filters = {}) {
    await init();
    const minutes = Math.max(1, Number(windowMinutes) || 60);
    const since = new Date(Date.now() - minutes * 60_000).toISOString();
    const metricParams = [since];
    const tenantClause = filters.tenantId ? " AND tenant_id = ?" : "";
    if (filters.tenantId) {
      metricParams.push(String(filters.tenantId));
    }

    const attacksPerMinute = await all(
      db,
      `SELECT strftime('%Y-%m-%d %H:%M', timestamp) AS minute, COUNT(*) AS count
       FROM security_events
       WHERE timestamp >= ? AND blocked = 1${tenantClause}
       GROUP BY minute
       ORDER BY minute DESC
       LIMIT 120`,
      metricParams
    );

    const topAttackerIps = await all(
      db,
      `SELECT ip, COUNT(*) AS count
       FROM security_events
       WHERE timestamp >= ? AND blocked = 1 AND ip <> ''${tenantClause}
       GROUP BY ip
       ORDER BY count DESC
       LIMIT 20`,
      metricParams
    );

    const topRuleIds = await all(
      db,
      `SELECT rule_id, COUNT(*) AS count
       FROM security_events
       WHERE timestamp >= ? AND blocked = 1 AND rule_id <> ''${tenantClause}
       GROUP BY rule_id
       ORDER BY count DESC
       LIMIT 20`,
      metricParams
    );

    const latencyAgg = await get(
      db,
      `SELECT
         AVG(latency_ms) AS avgLatency,
         SUM(CASE WHEN source = 'AI_FAIL_OPEN' THEN 1 ELSE 0 END) AS aiTimeoutCount,
         SUM(CASE WHEN source = 'AI_ENGINE' THEN 1 ELSE 0 END) AS aiPathCount
       FROM security_events
       WHERE timestamp >= ?${tenantClause}`,
      metricParams
    );

    const fpQueue = await listFalsePositiveQueue(100, {
      tenantId: filters.tenantId,
    }, 0);

    return {
      windowMinutes: minutes,
      attacksPerMinute,
      topAttackerIps,
      topRuleIds,
      aiLatencyAndTimeout: {
        avgLatencyMs: Number((latencyAgg?.avgLatency || 0).toFixed(2)),
        aiTimeoutCount: Number(latencyAgg?.aiTimeoutCount || 0),
        aiPathCount: Number(latencyAgg?.aiPathCount || 0),
      },
      falsePositiveQueue: fpQueue.items,
    };
  }

  async function markFalsePositive(eventId, note = "") {
    await init();
    await run(
      db,
      `INSERT INTO false_positive_reviews (event_id, note, reviewed_at) VALUES (?, ?, ?)`,
      [Number(eventId), String(note || ""), new Date().toISOString()]
    );
  }

  async function blockIp(ip, reason = "manual") {
    await init();
    await run(
      db,
      `INSERT OR REPLACE INTO blocklist_ips (ip, reason, created_at) VALUES (?, ?, ?)`,
      [String(ip), String(reason), new Date().toISOString()]
    );
  }

  async function unblockIp(ip) {
    await init();
    await run(db, `DELETE FROM blocklist_ips WHERE ip = ?`, [String(ip)]);
  }

  async function listBlockedIps() {
    await init();
    return all(db, `SELECT * FROM blocklist_ips ORDER BY created_at DESC`);
  }

  async function isBlockedIp(ip) {
    await init();
    const row = await get(db, `SELECT ip FROM blocklist_ips WHERE ip = ?`, [String(ip)]);
    return Boolean(row && row.ip);
  }

  async function recordHealth(snapshot = {}) {
    await init();
    await run(
      db,
      `INSERT INTO system_health_snapshots (timestamp, ai_up, ai_timeout_rate, queue_depth, metadata_json)
       VALUES (?, ?, ?, ?, ?)`,
      [
        new Date().toISOString(),
        snapshot.aiUp ? 1 : 0,
        Number(snapshot.aiTimeoutRate || 0),
        Number(snapshot.queueDepth || 0),
        JSON.stringify(snapshot.metadata || {}),
      ]
    );
  }

  async function loadPolicies() {
    await init();
    const defaultRow = await get(db, `SELECT policy_json FROM policy_default WHERE id = 1`);
    const routeRows = await all(
      db,
      `SELECT pattern, method, policy_json FROM policy_routes ORDER BY id ASC`
    );

    return {
      defaultPolicy: parseJSONSafe(defaultRow?.policy_json, null),
      routes: routeRows.map((r) => ({
        pattern: r.pattern,
        method: r.method,
        policy: parseJSONSafe(r.policy_json, {}),
      })),
    };
  }

  async function recordPolicyAudit(entry = {}) {
    await init();
    await run(
      db,
      `INSERT INTO policy_audit_log (
        timestamp, actor, action, target_type, target_key, before_json, after_json, metadata_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        toISO(entry.timestamp),
        String(entry.actor || "api"),
        String(entry.action || "UPDATE"),
        String(entry.targetType || "policy"),
        String(entry.targetKey || ""),
        entry.before !== undefined ? JSON.stringify(entry.before) : null,
        entry.after !== undefined ? JSON.stringify(entry.after) : null,
        JSON.stringify(entry.metadata || {}),
      ]
    );
  }

  async function saveDefaultPolicy(policy, actor = "api") {
    await init();
    const existing = await get(db, `SELECT policy_json FROM policy_default WHERE id = 1`);
    const before = parseJSONSafe(existing?.policy_json, null);
    await run(
      db,
      `INSERT INTO policy_default (id, policy_json, updated_at, updated_by)
       VALUES (1, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         policy_json = excluded.policy_json,
         updated_at = excluded.updated_at,
         updated_by = excluded.updated_by`,
      [JSON.stringify(policy || {}), new Date().toISOString(), String(actor || "api")]
    );
    await recordPolicyAudit({
      actor,
      action: before ? "UPDATE_DEFAULT" : "CREATE_DEFAULT",
      targetType: "default",
      targetKey: "default",
      before,
      after: policy || {},
    });
  }

  async function upsertRoutePolicy(pattern, method, policy, actor = "api") {
    await init();
    const existing = await get(
      db,
      `SELECT policy_json FROM policy_routes WHERE pattern = ? AND method = ?`,
      [String(pattern), String(method)]
    );
    const before = parseJSONSafe(existing?.policy_json, null);
    await run(
      db,
      `INSERT INTO policy_routes (pattern, method, policy_json, updated_at, updated_by)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(pattern, method) DO UPDATE SET
         policy_json = excluded.policy_json,
         updated_at = excluded.updated_at,
         updated_by = excluded.updated_by`,
      [
        String(pattern),
        String(method),
        JSON.stringify(policy || {}),
        new Date().toISOString(),
        String(actor || "api"),
      ]
    );
    await recordPolicyAudit({
      actor,
      action: before ? "UPDATE_ROUTE" : "CREATE_ROUTE",
      targetType: "route",
      targetKey: `${String(method)} ${String(pattern)}`,
      before,
      after: policy || {},
    });
  }

  async function deleteRoutePolicy(pattern, method, actor = "api") {
    await init();
    const existing = await get(
      db,
      `SELECT policy_json FROM policy_routes WHERE pattern = ? AND method = ?`,
      [String(pattern), String(method)]
    );
    const before = parseJSONSafe(existing?.policy_json, null);
    await run(
      db,
      `DELETE FROM policy_routes WHERE pattern = ? AND method = ?`,
      [String(pattern), String(method)]
    );
    if (before) {
      await recordPolicyAudit({
        actor,
        action: "DELETE_ROUTE",
        targetType: "route",
        targetKey: `${String(method)} ${String(pattern)}`,
        before,
        after: null,
      });
      return true;
    }
    return false;
  }

  async function listPolicyAudit(limit = 100, filters = {}, offset = 0) {
    await init();
    const params = [];
    const where = [];

    if (filters.actor) {
      where.push("actor = ?");
      params.push(String(filters.actor));
    }
    if (filters.action) {
      where.push("action = ?");
      params.push(String(filters.action));
    }
    if (filters.targetType) {
      where.push("target_type = ?");
      params.push(String(filters.targetType));
    }
    if (filters.targetKey) {
      where.push("target_key = ?");
      params.push(String(filters.targetKey));
    }
    if (filters.from) {
      where.push("timestamp >= ?");
      params.push(toISO(filters.from));
    }
    if (filters.to) {
      where.push("timestamp <= ?");
      params.push(toISO(filters.to));
    }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const totalRow = await get(
      db,
      `SELECT COUNT(*) AS total FROM policy_audit_log ${whereSql}`,
      params
    );

    const queryParams = params.slice();
    queryParams.push(clampLimit(limit, 100));
    queryParams.push(clampOffset(offset));
    const items = await all(
      db,
      `SELECT * FROM policy_audit_log ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?`,
      queryParams
    );

    return {
      items,
      total: Number(totalRow?.total || 0),
    };
  }

  return {
    init,
    recordEvent,
    listEvents,
    getMetrics,
    markFalsePositive,
    blockIp,
    unblockIp,
    listBlockedIps,
    isBlockedIp,
    recordHealth,
    loadPolicies,
    saveDefaultPolicy,
    upsertRoutePolicy,
    deleteRoutePolicy,
    listPolicyAudit,
    listFalsePositiveQueue,
    recordPolicyAudit,
  };
};
