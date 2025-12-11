/**
 * utils.js
 * Small helpers: signature generator for caching etc.
 */

const crypto = require("crypto");

module.exports = {
  // generate a short signature from feature set for caching
  signatureFromFeatures: (features) => {
    try {
      const copy = Object.assign({}, features);
      // drop timestamp and ip for generalization
      delete copy.ts;
      delete copy.ip;
      const s = JSON.stringify(copy);
      return crypto.createHash("sha256").update(s).digest("hex").slice(0, 32);
    } catch (e) {
      return Math.random().toString(36).slice(2, 10);
    }
  }
};
