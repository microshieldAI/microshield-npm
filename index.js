const staticRules = require("./lib/staticRules");
const featureExtractor = require("./lib/featureExtractor");
const aiClient = require("./lib/aiClient");
const logger = require("./lib/logger");
const utils = require("./lib/utils");
const rateLimit = require("express-rate-limit");
const { LRUCache } = require("lru-cache");

module.exports = function MicroShield(options = {}) {
  const config = {
    aiUrl: options.aiUrl || "http://127.0.0.1:8000/predict",
    mode: options.mode || "protect",
    failOpen: options.failOpen ?? true,
    sampleRate: 1, // 🔥 ALWAYS 1 FOR TESTING
    rateLimit: options.rateLimit || { windowMs: 60_000, max: 120 }
  };

  const aiCache = new LRUCache({ max: 1000, ttl: 1000 * 60 * 5 });

  const limiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.max,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) =>
      req.ip || req.headers["x-forwarded-for"] || req.connection.remoteAddress
  });

  return async function (req, res, next) {
    limiter(req, res, async () => {
      try {
        /* 1️⃣ STATIC RULES */
        if (staticRules.detect(req)) {
          logger.log(req, "STATIC_RULE");
          return res.status(403).json({ error: "Blocked (static rule)" });
        }

        /* 2️⃣ FEATURE EXTRACTION */
        const features = featureExtractor(req);

        /* 3️⃣ LEARN MODE */
        if (config.mode === "learn") {
          aiClient.sendSample(features).catch(() => {});
          return next();
        }

        /* 4️⃣ CACHE */
        const sig = utils.signatureFromFeatures(features);
        const cached = aiCache.get(sig);
        if (cached) {
          const cachedRisk = cached.risk.toLowerCase();
          if (cachedRisk.includes("high") || cachedRisk.includes("medium")) {
            logger.log(req, "AI_CACHE_BLOCK", cached.score);
            return res.status(403).json({ error: "Blocked (AI cached)" });
          }
          return next();
        }

        /* 5️⃣ AI CALL */
        let result;
        try {
          result = await aiClient.predict(config.aiUrl, features);
          console.log("AI RESULT:", result); // 🔥 SHOW FOR DEMO
        } catch (e) {
          if (config.failOpen) {
            logger.log(req, "AI_FAIL_OPEN");
            return next();
          }
          return res.status(503).json({ error: "Security engine unavailable" });
        }

        aiCache.set(sig, result);

        /* 6️⃣ DECISION LAYER (STRICT FOR DEMO) */
        const risk = result.risk.toLowerCase();
        if (risk.includes("high") || risk.includes("medium")) {
          logger.log(req, "AI_BLOCK", result.score);
          return res.status(403).json({ error: "Blocked (AI risk)" });
        }

        return next();
      } catch (err) {
        logger.logError(err);
        return next();
      }
    });
  };
};
