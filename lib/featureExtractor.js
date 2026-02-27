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

module.exports = function featureExtractor(req) {
  const body = safeStringify(req.body);
  const query = safeStringify(req.query);
  const combined = body + " " + query;

  return {
    pathLength: (req.path || "").length,
    bodySize: body.length,
    queryParams: Object.keys(req.query || {}).length,
    specialChars: countSpecialChars(combined),
    entropy: entropy(combined),
    methodPOST: req.method === "POST" ? 1 : 0
  };
};
