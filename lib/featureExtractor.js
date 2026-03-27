function safeStringify(obj) {
  try {
    return JSON.stringify(obj || {});
  } catch {
    return "";
  }
}

function countSpecialChars(s) {
  if (!s) return 0;
  const matches = s.match(/[^a-zA-Z0-9\s]/g);
  return matches ? matches.length : 0;
}

function entropy(s) {
  if (!s) return 0;
  const freq = {};
  for (let ch of s) freq[ch] = (freq[ch] || 0) + 1;
  const len = s.length;
  let ent = 0;
  for (let k in freq) {
    const p = freq[k] / len;
    ent -= p * Math.log2(p);
  }
  return Number(ent.toFixed(3));
}

function headerAnomalyScore(req) {
  const headers = req.headers || {};
  const keys = Object.keys(headers).map((k) => k.toLowerCase());
  let score = 0;

  if (!headers["user-agent"]) score += 0.3;
  if (req.method === "POST" && !headers["content-type"]) score += 0.2;
  if (!headers["accept"]) score += 0.1;
  if (keys.length > 40 || keys.length < 2) score += 0.2;
  if (String(headers["x-forwarded-for"] || "").split(",").length > 3) score += 0.2;

  return Number(Math.min(1, score).toFixed(3));
}

module.exports = function featureExtractor(req, behavior = {}) {
  const body = safeStringify(req.body);
  const query = safeStringify(req.query);
  const combined = body + " " + query;

  return {
    pathLength: (req.path || "").length,
    bodySize: body.length,
    queryParams: Object.keys(req.query || {}).length,
    specialChars: countSpecialChars(combined),
    entropy: entropy(combined),
    methodPOST: req.method === "POST" ? 1 : 0,
    ipReqPerMin: Number(behavior.ipReqPerMin || 0),
    ipReqPer5Min: Number(behavior.ipReqPer5Min || 0),
    routeReqPerMin: Number(behavior.routeReqPerMin || 0),
    routeReqPer5Min: Number(behavior.routeReqPer5Min || 0),
    uniquePathsPerMin: Number(behavior.uniquePathsPerMin || 0),
    postRatioPerMin: Number(behavior.postRatioPerMin || 0),
    failedLoginBurst1Min: Number(behavior.failedLoginBurst1Min || 0),
    uaRarityScore: Number(behavior.uaRarityScore || 0),
    payloadSimilarityScore: Number(behavior.payloadSimilarityScore || 0),
    headerAnomalyScore: headerAnomalyScore(req)
  };
};
