/**
 * featureExtractor.js
 * Convert a request into a small numeric feature vector (JS object).
 * Keep features fast to compute and robust.
 */

function safeStringify(obj) {
  try {
    return JSON.stringify(obj || {});
  } catch (e) {
    return "";
  }
}

function countSpecialChars(s) {
  if (!s) return 0;
  const matches = s.match(/[^a-zA-Z0-9\s]/g);
  return matches ? matches.length : 0;
}

function entropy(s) {
  if (!s || s.length === 0) return 0;
  const freq = {};
  for (let ch of s) freq[ch] = (freq[ch] || 0) + 1;
  const len = s.length;
  let ent = 0;
  for (let k in freq) {
    const p = freq[k] / len;
    ent -= p * Math.log2(p);
  }
  return Math.round(ent * 100) / 100; // two decimals
}

module.exports = function (req) {
  const path = req.path || "/";
  const body = safeStringify(req.body);
  const query = safeStringify(req.query);
  const headers = safeStringify(req.headers);

  const combined = body + " " + query;

  return {
    pathLength: path.length,
    bodySize: body.length,
    queryParams: Object.keys(req.query || {}).length,
    headerCount: Object.keys(req.headers || {}).length,
    specialChars: countSpecialChars(combined),
    methodPOST: req.method === "POST" ? 1 : 0,
    payloadEntropy: entropy(combined),
    ip: req.ip || req.headers["x-forwarded-for"] || "",
    ts: Date.now()
  };
};
