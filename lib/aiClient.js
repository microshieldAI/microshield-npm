/**
 * aiClient.js
 * Responsible for calling AI predict endpoint and a lightweight /train_sample endpoint.
 * Exposes:
 * - predict(aiUrl, features) -> Promise<"normal"|"suspicious">
 * - sendSample(trainUrl, features) -> Promise (non-blocking)
 */

const axios = require("axios");

module.exports = {
  predict: async (aiUrl, features) => {
    // aiUrl should be like http://host:5000/predict
    const res = await axios.post(aiUrl, features, { timeout: 3000 });
    // expected { result: "normal" } or { result: "suspicious" }
    if (res && res.data && res.data.result) return res.data.result;
    // fallback
    return "normal";
  },

  // send sample for later training (non-blocking)
  sendSample: async (trainUrl, features) => {
    try {
      await axios.post(trainUrl, features, { timeout: 2000 });
    } catch (e) {
      // ignore errors - training service is optional
    }
  }
};
