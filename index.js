/**
 * MicroShield AI - main middleware
 *
 * Usage:
 * const MicroShield = require("microshield-ai");
 * app.use(MicroShield({ aiUrl: "http://localhost:5000/predict", mode: "protect" }));
 *
 * Options:
 * - aiUrl: URL of AI engine predict endpoint
 * - mode: "learn" or "protect" (learn = collect features but do not block)
 * - failOpen: boolean (if true, when AI endpoint is down, allow request)
 */

const staticRules = require("./lib/staticRules");
const featureExtractor = require("./lib/featureExtractor");
const aiClient = require("./lib/aiClient");
const logger = require("./lib/logger");
const utils = require("./lib/utils");
const rateLimit = require("express-rate-limit");
const LRU = require("lru-cache");

module.exports = function MicroShield(options = {}) {
  const config = {
    aiUrl: options.aiUrl || process.env.MICROSHIELD_AI_URL || "http://localhost:5000/predict",
    mode: options.mode || process.env.MICROSHIELD_MODE || "protect", // "learn" or "protect"
    failOpen: options.failOpen !== undefined ? options.failOpen : true,
    sampleRate: options.sampleRate || 1, // 1 means sample every request; increase to lower sampling
    rateLimit: options.rateLimit || { windowMs: 60_000, max: 120 } // per IP
  };

  // simple in-memory cache to reduce repeated AI calls for identical payload signatures
  const aiCache = new LRU({ max: 1000, ttl: 1000 * 60 * 5 }); // 5 minutes

  // express-rate-limit instance (per-IP)
  const limiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.max,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip || req.headers["x-forwarded-for"] || req.connection.remoteAddress
  });

  // attach mode information to middleware
  return async function (req, res, next) {
    try {
      // quick checks: only JSON / form / query requests supported for feature extraction
      // 1) Apply the per-IP rate limiter (fast)
      limiter(req, res, async () => {
        // 2) Static rules: immediate known-attack detection
        const staticDetected = staticRules.detect(req);
        if (staticDetected) {
          logger.log(req, "STATIC_RULE");
          return res.status(403).json({ error: "Blocked by MicroShield (static rule)" });
        }

        // 3) In learning mode we collect features but do NOT block (useful initial stage)
        const features = featureExtractor(req);

        if (config.mode === "learn") {
          // send features to training endpoint (non-blocking)
          aiClient.sendSample(config.aiUrl.replace("/predict", "/train_sample"), features).catch(() => {});
          return next();
        }

        // 4) Sample check (optional) - avoid calling AI for every request if sampleRate > 1
        if (config.sampleRate > 1 && Math.floor(Math.random() * config.sampleRate) !== 0) {
          return next();
        }

        // 5) Cache lookup to avoid repetitive calls
        const cacheKey = utils.signatureFromFeatures(features);
        const cached = aiCache.get(cacheKey);
        if (cached) {
          if (cached === "suspicious") {
            logger.log(req, "AI_CACHE");
            return res.status(403).json({ error: "Blocked by MicroShield (AI - cached)" });
          } else {
            return next();
          }
        }

        // 6) Call AI engine
        let verdict = "normal";
        try {
          verdict = await aiClient.predict(config.aiUrl, features);
        } catch (err) {
          // if AI fails and failOpen true → allow request; otherwise block safe fallback
          if (config.failOpen) {
            // log AI failure with warning
            logger.log(req, "AI_ERROR_FAILOPEN");
            return next();
          } else {
            logger.log(req, "AI_ERROR_FAILCLOSE");
            return res.status(500).json({ error: "Security engine unavailable" });
          }
        }

        // store in cache
        aiCache.set(cacheKey, verdict);

        if (verdict === "suspicious") {
          logger.log(req, "AI_MODEL");
          return res.status(403).json({ error: "Blocked by MicroShield (AI detection)" });
        }

        // safe path
        return next();
      });
    } catch (e) {
      // unexpected error - fail open and log
      logger.logError(e);
      return next();
    }
  };
};
