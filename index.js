const staticRules = require("./lib/staticRules");
const featureExtractor = require("./lib/featureExtractor");
const aiClient = require("./lib/aiClient");
const logger = require("./lib/logger");
const utils = require("./lib/utils");
const createBehaviorTracker = require("./lib/behaviorTracker");
const createTelemetryStore = require("./lib/telemetryStore");
const createPolicyEngine = require("./lib/policyEngine");
const { LRUCache } = require("lru-cache");
const crypto = require("crypto");

module.exports = function MicroShield(options = {}) {
  const config = {
    aiUrl: options.aiUrl || "http://127.0.0.1:8000/predict",
    mode: options.mode || "protect",
    failOpen: options.failOpen ?? true,
    sampleRate: 1, // 🔥 ALWAYS 1 FOR TESTING
    rateLimit: options.rateLimit || { windowMs: 60_000, max: 120 },
    botThresholds: options.botThresholds || {
      ipReqPerMin: 90,
      routeReqPerMin: 60,
      uniquePathsPerMin: 30,
    },
    telemetry: options.telemetry || {
      enabled: true,
      dbPath: "",
    },
    defaultTenantId: options.defaultTenantId || "public",
  };

  function setSourceHeader(res, source) {
    if (source) {
      res.setHeader("X-Microshield-Source", source);
    }
  }

  function normalizeRisk(rawRisk) {
    if (typeof rawRisk !== "string") return "";
    const v = rawRisk.trim().toLowerCase();
    if (v === "high" || v === "high risk") return "high";
    if (v === "medium" || v === "medium risk") return "medium";
    if (v === "low" || v === "low risk") return "low";
    return "";
  }

  const aiCache = new LRUCache({ max: 1000, ttl: 1000 * 60 * 5 });
  const behaviorTracker = createBehaviorTracker({ windowMs: 60_000 });
  const telemetryStore = options.telemetryStore || createTelemetryStore({ dbPath: config.telemetry.dbPath || undefined });
  const policyEngine = options.policyEngine || createPolicyEngine({
    defaultPolicy: {
      enableStaticRules: true,
      enableBehaviorGate: true,
      enableAI: true,
      failOpen: config.failOpen,
      aiBlockRisks: ["medium", "high"],
      rateLimit: config.rateLimit,
      botThresholds: config.botThresholds,
      ...(options.defaultPolicy || {}),
    },
  });
  telemetryStore.init().catch(() => {});
  const rateState = new Map();

  function getClientIp(req) {
    return req.ip || req.socket?.remoteAddress || "";
  }

  function getTenantId(req) {
    const fromReq = req._tenantId || req.headers?.["x-tenant-id"];
    const tenant = String(fromReq || config.defaultTenantId || "public").trim();
    return tenant || "public";
  }

  function getUserId(req) {
    const fromReq = req._userId || req.headers?.["x-user-id"];
    const user = String(fromReq || "anonymous").trim();
    return user || "anonymous";
  }

  async function writeDecisionEvent(req, decision = {}) {
    if (!config.telemetry.enabled) return;
    try {
      await telemetryStore.recordEvent({
        timestamp: new Date().toISOString(),
        tenantId: getTenantId(req),
        userId: getUserId(req),
        traceId: req._microshieldTraceId || "",
        ip: getClientIp(req),
        method: req.method,
        route: req.path,
        source: decision.source || "UNKNOWN",
        ruleId: decision.ruleId || "",
        risk: decision.risk || "",
        score: Number.isFinite(Number(decision.score)) ? Number(decision.score) : null,
        blocked: Boolean(decision.blocked),
        latencyMs: Date.now() - (req._microshieldStartedAt || Date.now()),
        statusCode: Number(decision.statusCode || 0),
        userAgent: String(req.headers?.["user-agent"] || ""),
        metadata: {
          cache: Boolean(decision.cache),
          reason: decision.reason || "",
          behavior: decision.behavior || null,
        },
      });
    } catch {
      // Telemetry should never break request flow.
    }
  }

  async function applyPolicyRateLimit(req, res, policy) {
    const rateLimitConfig = policy && policy.rateLimit ? policy.rateLimit : config.rateLimit;
    const windowMs = Math.max(1000, Number(rateLimitConfig.windowMs) || 60_000);
    const max = Math.max(0, Number(rateLimitConfig.max) || 0);

    if (max <= 0) return false;

    const now = Date.now();
    const ip = getClientIp(req) || "unknown";
    const route = req.path || "/";
    const key = `${ip}:${req.method}:${route}:${windowMs}:${max}`;
    const state = rateState.get(key) || { count: 0, resetAt: now + windowMs };

    if (now > state.resetAt) {
      state.count = 0;
      state.resetAt = now + windowMs;
    }

    state.count += 1;
    rateState.set(key, state);

    if (state.count <= max) return false;

    setSourceHeader(res, "RATE_LIMIT");
    await writeDecisionEvent(req, {
      source: "RATE_LIMIT",
      ruleId: "RATE_LIMIT",
      blocked: true,
      statusCode: 429,
      reason: `Rate limit exceeded (${max}/${windowMs}ms)`,
    });
    res.status(429).send("Too many requests, please try again later.");
    return true;
  }

  return async function (req, res, next) {
    req._microshieldStartedAt = Date.now();
    req._microshieldTraceId = req.headers["x-trace-id"] || crypto.randomUUID();

    try {
      let decisionSource = null;
      const resolved = policyEngine.resolve(req);
      const policy = resolved.policy;

      if (await applyPolicyRateLimit(req, res, policy)) {
        return;
      }

      if (await telemetryStore.isBlockedIp(getClientIp(req))) {
        decisionSource = "STATIC_RULE";
        setSourceHeader(res, decisionSource);
        await writeDecisionEvent(req, {
          source: decisionSource,
          ruleId: "BLOCKLIST_IP",
          blocked: true,
          statusCode: 403,
          reason: "IP found in blocklist",
        });
        return res.status(403).json({
          error: "Blocked (blocklist)",
          source: decisionSource,
          ruleId: "BLOCKLIST_IP",
        });
      }

      /* 1️⃣ STATIC RULES */
      if (policy.enableStaticRules !== false) {
        const staticResult = staticRules.detect(req);
        const staticMatched = staticResult === true || (staticResult && staticResult.matched);
        if (staticMatched) {
          decisionSource = "STATIC_RULE";
          logger.log(req, decisionSource, null, {
            ruleId: staticResult && staticResult.ruleId,
            reason: staticResult && staticResult.message,
            matchedValue: staticResult && staticResult.matchedValue,
          });
          await writeDecisionEvent(req, {
            source: decisionSource,
            ruleId: staticResult && staticResult.ruleId,
            blocked: true,
            statusCode: 403,
            reason: staticResult && staticResult.message,
          });
          setSourceHeader(res, decisionSource);
          return res.status(403).json({
            error: "Blocked (static rule)",
            source: decisionSource,
            ruleId: staticResult && staticResult.ruleId,
          });
        }
      }

      /* 1.5️⃣ BOT BEHAVIOR GATE */
      const behavior = behaviorTracker.record(req);
      const botThresholds = policy.botThresholds || config.botThresholds;
      if (policy.enableBehaviorGate !== false) {
        const isBotBurst =
          behavior.ipReqPerMin >= botThresholds.ipReqPerMin ||
          behavior.routeReqPerMin >= botThresholds.routeReqPerMin ||
          behavior.uniquePathsPerMin >= botThresholds.uniquePathsPerMin;

        if (isBotBurst) {
          decisionSource = "STATIC_RULE";
          logger.log(req, decisionSource, null, {
            ruleId: "BOT_BURST_RATE",
            reason: "Behavior thresholds exceeded",
            behavior,
          });
          await writeDecisionEvent(req, {
            source: decisionSource,
            ruleId: "BOT_BURST_RATE",
            blocked: true,
            statusCode: 403,
            reason: "Behavior thresholds exceeded",
            behavior,
          });
          setSourceHeader(res, decisionSource);
          return res.status(403).json({
            error: "Blocked (bot burst)",
            source: decisionSource,
            ruleId: "BOT_BURST_RATE",
          });
        }
      }

      /* 2️⃣ FEATURE EXTRACTION */
      const features = featureExtractor(req, behavior);

      /* 3️⃣ LEARN MODE */
      if (config.mode === "learn") {
        aiClient.sendSample(features).catch(() => {});
        await writeDecisionEvent(req, {
          source: "LEARN_MODE",
          blocked: false,
          statusCode: 200,
        });
        return next();
      }

      if (policy.enableAI === false) {
        setSourceHeader(res, "POLICY_BYPASS");
        await writeDecisionEvent(req, {
          source: "POLICY_BYPASS",
          ruleId: "AI_DISABLED_BY_POLICY",
          blocked: false,
          statusCode: 200,
          reason: "AI path disabled by route policy",
        });
        return next();
      }

      /* 4️⃣ CACHE */
      const sig = utils.signatureFromFeatures(features);
      const cached = aiCache.get(sig);
      const blockRisks = Array.isArray(policy.aiBlockRisks) && policy.aiBlockRisks.length
        ? policy.aiBlockRisks
        : ["medium", "high"];
      if (cached) {
        const cachedRisk = normalizeRisk(cached.risk);
        if (blockRisks.includes(cachedRisk)) {
          decisionSource = "AI_ENGINE";
          logger.log(req, decisionSource, cached.score, { cache: true, risk: cachedRisk });
          const cachedReason = String(cached.reason || `Cached AI decision risk=${cachedRisk}`);
          await writeDecisionEvent(req, {
            source: decisionSource,
            ruleId: `AI_CACHE_BLOCK_${cachedRisk.toUpperCase() || "UNKNOWN"}`,
            risk: cachedRisk,
            score: cached.score,
            blocked: true,
            statusCode: 403,
            cache: true,
            reason: cachedReason,
          });
          setSourceHeader(res, decisionSource);
          return res.status(403).json({
            error: "Blocked (AI cached)",
            source: decisionSource,
            ruleId: `AI_CACHE_BLOCK_${cachedRisk.toUpperCase() || "UNKNOWN"}`,
            risk: cachedRisk,
            score: cached.score,
            reason: cachedReason,
          });
        }
        decisionSource = "AI_ENGINE";
        await writeDecisionEvent(req, {
          source: decisionSource,
          risk: cachedRisk,
          score: cached.score,
          blocked: false,
          statusCode: 200,
          cache: true,
        });
        setSourceHeader(res, decisionSource);
        return next();
      }

      /* 5️⃣ AI CALL */
      let result;
      try {
        result = await aiClient.predict(config.aiUrl, features);
        console.log("AI RESULT:", result); // 🔥 SHOW FOR DEMO
      } catch (e) {
        if (policy.failOpen !== false) {
          decisionSource = "AI_FAIL_OPEN";
          logger.log(req, decisionSource, null, { reason: "AI engine unavailable" });
          await writeDecisionEvent(req, {
            source: decisionSource,
            ruleId: "AI_UNAVAILABLE_FAIL_OPEN",
            blocked: false,
            statusCode: 200,
            reason: "AI engine unavailable",
          });
          setSourceHeader(res, decisionSource);
          return next();
        }
        await writeDecisionEvent(req, {
          source: "AI_ENGINE",
          ruleId: "AI_UNAVAILABLE_FAIL_CLOSED",
          blocked: true,
          statusCode: 503,
          reason: "Security engine unavailable",
        });
        return res.status(503).json({ error: "Security engine unavailable" });
      }

      aiCache.set(sig, result);

      /* 6️⃣ DECISION LAYER (STRICT FOR DEMO) */
      const risk = normalizeRisk(result.risk);
      if (!risk) {
        throw new Error("AI response missing valid risk enum");
      }
      decisionSource = "AI_ENGINE";
      setSourceHeader(res, decisionSource);
      if (blockRisks.includes(risk)) {
        logger.log(req, decisionSource, result.score, { risk });
        behaviorTracker.markOutcome(req, 403);
        const aiReason = String(result.reason || `Model classified request as ${risk} risk (score=${Number(result.score).toFixed(4)})`);
        const aiRuleId = `AI_RISK_BLOCK_${risk.toUpperCase()}`;
        await writeDecisionEvent(req, {
          source: decisionSource,
          ruleId: aiRuleId,
          risk,
          score: result.score,
          blocked: true,
          statusCode: 403,
          reason: aiReason,
        });
        return res.status(403).json({
          error: "Blocked (AI risk)",
          source: decisionSource,
          ruleId: aiRuleId,
          risk,
          score: result.score,
          reason: aiReason,
        });
      }

      behaviorTracker.markOutcome(req, 200);
      await writeDecisionEvent(req, {
        source: decisionSource,
        risk,
        score: result.score,
        blocked: false,
        statusCode: 200,
      });

      return next();
    } catch (err) {
      logger.logError(err);
      await writeDecisionEvent(req, {
        source: "MIDDLEWARE_ERROR",
        ruleId: "UNHANDLED_EXCEPTION",
        blocked: false,
        statusCode: 200,
        reason: err && err.message,
      });
      return next();
    }
  };
};
