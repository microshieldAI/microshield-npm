/**
 * staticRules.js
 * Rule-based detection for known attack patterns
 * (SQLi, XSS, Traversal, Command Injection)
 */

const MAX_BODY_BYTES = 1024 * 1024; // 1MB

function bodyToString(req) {
  try {
    if (req.body && typeof req.body === "object") return JSON.stringify(req.body);
    if (typeof req.body === "string") return req.body;
    return "";
  } catch {
    return "";
  }
}

// Safely decode URL-encoded payloads
function safeDecode(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

module.exports = {
  detect: (req) => {
    const bodyStr = bodyToString(req);
    const queryStr = JSON.stringify(req.query || {});
    const headersStr = JSON.stringify(req.headers || {});

    // Combine and limit size
    const rawCombined = (bodyStr + " " + queryStr + " " + headersStr).slice(0, 20000);

    // 🔥 Decode encoded payloads (IMPORTANT FIX)
    const combined = safeDecode(rawCombined);

    /* 1️⃣ Large body protection */
    if (bodyStr.length > MAX_BODY_BYTES) return true;

    /* 2️⃣ SQL Injection patterns */
    const sqli = /\b(union\s+select|or\s+1=1|--\s|;\s*drop\s+table)\b/i;
    if (sqli.test(combined)) return true;

    /* 3️⃣ XSS patterns */
    const xss = /(<script\b|javascript:|onerror=|onload=|<svg\b|<img\b)/i;
    if (xss.test(combined)) return true;

    /* 4️⃣ Path traversal */
    const pathTraversal = /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)/i;
    if (pathTraversal.test(combined)) return true;

    /* 5️⃣ Command injection */
    const cmd = /(;|\|\||&&|\$\(.*\)|`.*`)/;
    if (cmd.test(combined)) return true;

    /* 6️⃣ Suspicious user-agents */
    const ua = (req.headers["user-agent"] || "").toLowerCase();
    const suspiciousUAs = ["sqlmap", "nmap", "nikto", "fuzzer", "curl"];
    for (const s of suspiciousUAs) {
      if (ua.includes(s)) return true;
    }

    /* 7️⃣ Content-Type mismatch */
    const ct = (req.headers["content-type"] || "").toLowerCase();
    if (ct.includes("application/json") && bodyStr.length === 0 && req.method === "POST") {
      return true;
    }

    return false;
  }
};
