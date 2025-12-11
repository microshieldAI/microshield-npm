/**
 * logger.js
 * Simple file-based logger for blocked/suspicious requests.
 * You can extend to MongoDB or remote logging later.
 */

const fs = require("fs");
const path = require("path");

const LOG_DIR = path.join(process.cwd(), "logs");
const LOG_FILE = path.join(LOG_DIR, "microshield.log");

if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

function append(obj) {
  const line = JSON.stringify(obj);
  fs.appendFileSync(LOG_FILE, line + "\n");
}

module.exports = {
  log: (req, origin = "UNKNOWN") => {
    try {
      const entry = {
        time: new Date().toISOString(),
        origin,
        ip: req.ip || req.headers["x-forwarded-for"] || "",
        method: req.method,
        path: req.path,
        headers: { "user-agent": req.headers["user-agent"] || "" },
        snippet: (req.body && JSON.stringify(req.body).slice(0, 300)) || "",
      };
      append(entry);
    } catch (e) {
      // swallow errors - logger should not crash middleware
      console.error("Logger error:", e.message || e);
    }
  },

  logError: (err) => {
    try {
      append({ time: new Date().toISOString(), error: (err && err.message) || String(err) });
    } catch (e) {
      // ignore
    }
  }
};
