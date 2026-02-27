const axios = require("axios");

module.exports = {
  predict: async (aiUrl, features) => {
    const res = await axios.post(aiUrl, features, { timeout: 3000 });

    // Expected: { score: number, risk: "low"|"medium"|"high" }
    if (res && res.data && typeof res.data.risk === "string") {
      return res.data;
    }

    // Safe fallback
    return { score: 0, risk: "low" };
  },

  sendSample: async () => {
    // Adaptive learning placeholder (future)
    return;
  }
};
