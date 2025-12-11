/**
 * staticRules.js
 * Very small rule set for known patterns.
 * Add/extend patterns as needed.
 */

const MAX_BODY_BYTES = 1024 * 1024; // 1MB

function bodyToString(req) {
  try {
    if (req.body && typeof req.body === "object") return JSON.stringify(req.body);
    if (typeof req.body === "string") return req.body;
    return "";
  } catch (e) {
    return "";
  }
}

module.exports = {
  detect: (req) => {
    const bodyStr = bodyToString(req);
    const queryStr = JSON.stringify(req.query || {});
    const headersStr = JSON.stringify(req.headers || {});
    const combined = (bodyStr + " " + queryStr + " " + headersStr).slice(0, 20000);

    // 1) large body
    if (bodyStr.length > MAX_BODY_BYTES) return true;

    // 2) SQL injection keywords (simple)
    const sqli = /\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|WHERE|OR\s+1=1|--|;--)\b/i;
    if (sqli.test(combined)) return true;

    // 3) XSS-like patterns
    const xss = /(<script\b|javascript:|onerror=|onload=|<svg\b|<img\b)/i;
    if (xss.test(combined)) return true;

    // 4) Path traversal
    const pathTraversal = /(\.\.\/|%2e%2e%2f)/i;
    if (pathTraversal.test(combined)) return true;

    // 5) Command injection tokens
    const cmd = /(;|\|\||&&|\$\(.*\)|`.*`)/;
    if (cmd.test(combined)) return true;

    // 6) suspicious user-agents (simple checks)
    const ua = (req.headers['user-agent'] || "").toLowerCase();
    const suspiciousUAs = ["sqlmap", "nmap", "nikto", "fuzzer"];
    for (const s of suspiciousUAs) {
      if (ua.includes(s)) return true;
    }

    // 7) basic content-type vs body mismatch (e.g., expecting JSON)
    const ct = (req.headers['content-type'] || "").toLowerCase();
    if (ct && ct.includes("application/json") && bodyStr.length === 0 && req.method === "POST") {
      return true;
    }

    return false;
  }
};
