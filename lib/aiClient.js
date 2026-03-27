const axios = require("axios");

function normalizeRisk(rawRisk) {
  if (typeof rawRisk !== "string") return "";
  const v = rawRisk.trim().toLowerCase();
  if (v === "high" || v === "high risk") return "high";
  if (v === "medium" || v === "medium risk") return "medium";
  if (v === "low" || v === "low risk") return "low";
  return "";
}

module.exports = {
  predict: async (aiUrl, features) => {
    const res = await axios.post(aiUrl, features, { timeout: 3000 });

    // Expected: { score: number, risk: "low"|"medium"|"high" }
    if (res && res.data) {
      const risk = normalizeRisk(res.data.risk);
      const score = Number(res.data.score);
      if (risk && Number.isFinite(score)) {
        return { score, risk };
      }
    }

    throw new Error("Invalid AI response schema");
  },

  sendSample: async () => {
    // Adaptive learning placeholder (future)
    return;
  }
};
