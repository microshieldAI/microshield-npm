const WINDOW_1M = 60_000;
const WINDOW_5M = 300_000;

function nowMs() {
  return Date.now();
}

function pruneOld(events, minTs) {
  let i = 0;
  while (i < events.length && events[i].ts < minTs) {
    i += 1;
  }
  if (i > 0) events.splice(0, i);
}

module.exports = function createBehaviorTracker(options = {}) {
  const windowMs = Number(options.windowMs) > 0 ? Number(options.windowMs) : WINDOW_1M;
  const ipEvents = new Map();
  const ipEvents5m = new Map();
  const uaSeen = new Map();
  const payloadSeen = new Map();
  const failedLoginEvents = new Map();

  function getIp(req) {
    return (
      req.ip ||
      req.headers["x-forwarded-for"] ||
      req.connection?.remoteAddress ||
      "unknown"
    );
  }

  function record(req) {
    const ts = nowMs();
    const minTs = ts - windowMs;
    const minTs5m = ts - WINDOW_5M;
    const ip = getIp(req);
    const path = req.path || "/";
    const method = req.method || "GET";
    const ua = String(req.headers?.["user-agent"] || "unknown").toLowerCase();
    const payloadKey = JSON.stringify(req.body || {});

    const events = ipEvents.get(ip) || [];
    events.push({ ts, path, method });
    pruneOld(events, minTs);
    ipEvents.set(ip, events);

    const events5m = ipEvents5m.get(ip) || [];
    events5m.push({ ts, path, method });
    pruneOld(events5m, minTs5m);
    ipEvents5m.set(ip, events5m);

    // Track seen frequency for rarity style signals.
    uaSeen.set(ua, (uaSeen.get(ua) || 0) + 1);
    payloadSeen.set(payloadKey, (payloadSeen.get(payloadKey) || 0) + 1);

    let routeReqPerMin = 0;
    let postCount = 0;
    const uniquePaths = new Set();

    for (const ev of events) {
      uniquePaths.add(ev.path);
      if (ev.path === path) routeReqPerMin += 1;
      if (ev.method === "POST") postCount += 1;
    }

    const ipReqPerMin = events.length;
    const ipReqPer5Min = events5m.length;
    const uniquePathsPerMin = uniquePaths.size;
    const postRatioPerMin = ipReqPerMin > 0 ? Number((postCount / ipReqPerMin).toFixed(3)) : 0;

    let routeReqPer5Min = 0;
    for (const ev of events5m) {
      if (ev.path === path) routeReqPer5Min += 1;
    }

    // Rarity score: first-seen UA gets close to 1, popular UA trends toward 0.
    const uaCount = uaSeen.get(ua) || 1;
    const uaRarityScore = Number((1 / Math.sqrt(uaCount)).toFixed(3));

    // Similarity score: repeated same payload yields higher similarity.
    const payloadCount = payloadSeen.get(payloadKey) || 1;
    const payloadSimilarityScore = Number(Math.min(1, payloadCount / 20).toFixed(3));

    const failedBurst = failedLoginEvents.get(ip) || [];
    pruneOld(failedBurst, minTs);
    failedLoginEvents.set(ip, failedBurst);
    const failedLoginBurst1Min = failedBurst.length;

    return {
      ipReqPerMin,
      ipReqPer5Min,
      routeReqPerMin,
      routeReqPer5Min,
      uniquePathsPerMin,
      postRatioPerMin,
      uaRarityScore,
      payloadSimilarityScore,
      failedLoginBurst1Min,
    };
  }

  function markOutcome(req, statusCode) {
    const ts = nowMs();
    const ip = getIp(req);
    const path = String(req.path || "").toLowerCase();
    const method = String(req.method || "GET").toUpperCase();
    const isLoginAttempt = method === "POST" && path.includes("login");
    const isFailed = Number(statusCode) >= 400;

    if (isLoginAttempt && isFailed) {
      const events = failedLoginEvents.get(ip) || [];
      events.push({ ts });
      pruneOld(events, ts - WINDOW_1M);
      failedLoginEvents.set(ip, events);
    }
  }

  return { record, markOutcome };
};
