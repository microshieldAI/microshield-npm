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

function decodeMulti(str, rounds = 2) {
  let out = str;
  for (let i = 0; i < rounds; i += 1) {
    const next = safeDecode(out);
    if (next === out) break;
    out = next;
  }
  return out;
}

function matchRule(ruleId, message, matched) {
  return {
    matched: true,
    ruleId,
    message,
    matchedValue: matched || "",
  };
}

function noMatch() {
  return { matched: false };
}

module.exports = {
  detect: (req) => {
    const bodyStr = bodyToString(req);
    const queryStr = JSON.stringify(req.query || {});
    const headersStr = JSON.stringify(req.headers || {});
    const payloadCombined = decodeMulti((bodyStr + " " + queryStr).slice(0, 20000), 3);

    // Combine and limit size
    const rawCombined = (bodyStr + " " + queryStr + " " + headersStr).slice(0, 20000);

    // 🔥 Decode encoded payloads (IMPORTANT FIX)
    const combined = decodeMulti(rawCombined, 3);

    /* 1️⃣ Large body protection */
    if (bodyStr.length > MAX_BODY_BYTES) {
      return matchRule("BODY_TOO_LARGE", "Request body exceeds allowed size");
    }

    /* 2️⃣ SQL Injection patterns */
    // Covers classic and quoted tautology payloads like: ' OR '1'='1
    const sqli = /(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\band\s+1\s*=\s*1\b|['"]\s*(or|and)\s*['"]?\d+['"]?\s*=\s*['"]?\d+['"]?|--\s|;\s*drop\s+table\b|information_schema|sleep\s*\(|benchmark\s*\()/i;
    const sqliHit = combined.match(sqli);
    if (sqliHit) {
      return matchRule("SQLI_PATTERN", "Detected SQL injection signature", sqliHit[0]);
    }

    /* 3️⃣ XSS patterns */
    const xss = /(<script\b|javascript:|onerror=|onload=|<svg\b|<img\b|document\.cookie|alert\s*\()/i;
    const xssHit = combined.match(xss);
    if (xssHit) {
      return matchRule("XSS_PATTERN", "Detected XSS signature", xssHit[0]);
    }

    /* 4️⃣ Path traversal */
    const pathTraversal = /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|\/etc\/passwd|\/windows\/win\.ini)/i;
    const pathTraversalHit = combined.match(pathTraversal);
    if (pathTraversalHit) {
      return matchRule("PATH_TRAVERSAL", "Detected path traversal signature", pathTraversalHit[0]);
    }

    /* 5️⃣ Command injection */
    const cmd = /(;|\|\||&&|\$\(.*\)|`.*`|\b(cat|ls|wget|curl|powershell|cmd\.exe)\b)/i;
    const cmdHit = payloadCombined.match(cmd);
    if (cmdHit) {
      return matchRule("COMMAND_INJECTION", "Detected command injection signature", cmdHit[0]);
    }

    /* 6️⃣ Suspicious user-agents */
    const ua = (req.headers["user-agent"] || "").toLowerCase();
    const suspiciousUAs = [
      "sqlmap",
      "hydra",
      "nmap",
      "nikto",
      "ffuf",
      "wfuzz",
      "gobuster",
      "dirbuster",
      "acunetix",
      "zgrab",
      "masscan",
      "python-requests",
      "go-http-client",
    ];
    for (const s of suspiciousUAs) {
      if (ua.includes(s)) {
        return matchRule("SUSPICIOUS_UA", "Detected automated scanning user-agent", s);
      }
    }

    /* 7️⃣ Recon/scanner paths */
    const path = (req.path || "").toLowerCase();
    const scannerPaths = [
      "/.env",
      "/wp-admin",
      "/wp-login.php",
      "/phpmyadmin",
      "/.git/config",
      "/server-status",
      "/actuator",
      "/.aws/credentials",
    ];
    for (const p of scannerPaths) {
      if (path.includes(p)) {
        return matchRule("SCANNER_PATH", "Detected reconnaissance path probing", p);
      }
    }

    /* 8️⃣ Content-Type mismatch */
    const ct = (req.headers["content-type"] || "").toLowerCase();
    if (ct.includes("application/json") && bodyStr.length === 0 && req.method === "POST") {
      return matchRule("CONTENT_TYPE_MISMATCH", "JSON content-type without JSON body");
    }

    return noMatch();
  }
};
