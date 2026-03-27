# AI Engine Integration Guide

This document explains how a separate ai-engine repository should integrate with microshield-npm.

## Goal

microshield-npm performs edge request inspection in Express and sends extracted request features to ai-engine.
ai-engine returns a normalized risk judgment that microshield-npm can enforce.

## Responsibilities Split

microshield-npm:
- Request interception and rate limiting
- Static attack signature checks
- Feature extraction from HTTP request metadata/payload shape
- Cache short-term risk verdicts
- Enforce allow or block in middleware
- Security event logging

ai-engine:
- Receives feature payload
- Performs model inference and policy reasoning
- Optionally calls Claude (or another LLM) for judgment explanation and confidence refinement
- Returns strict risk schema expected by microshield-npm

## API Contract Between Repos

Endpoint (default in middleware):
- POST /predict

Request body (from microshield-npm):

{
  "pathLength": 12,
  "bodySize": 44,
  "queryParams": 2,
  "specialChars": 5,
  "entropy": 3.241,
  "methodPOST": 1
}

Response body (required shape):

{
  "score": 0.82,
  "risk": "high"
}

Response rules:
- risk must be a string such as low, medium, or high.
- score should be numeric in a consistent scale (recommended 0 to 1).
- Keep response latency low (middleware client timeout is currently 3000 ms).

## Claude Judging Pattern (Recommended)

If ai-engine uses Claude for judging, use a structured two-stage decision:

1. Model signal stage:
- Compute baseline risk score from deterministic/ML features.

2. Claude reasoning stage:
- Send compact structured context to Claude.
- Ask for bounded output schema only.
- Return risk and confidence/explanation.

Recommended ai-engine internal output schema:

{
  "risk": "low|medium|high",
  "score": 0.0,
  "confidence": 0.0,
  "reasons": ["reason-1", "reason-2"],
  "version": "policy-2026-03"
}

Mapping to microshield-npm response:
- score -> score
- risk -> risk
- keep other fields internal unless middleware contract is extended

## Process Flow Across Both Repos

1. Client sends HTTP request to Express app.
2. microshield-npm static rules evaluate known bad patterns.
3. If static match, block immediately and log STATIC_RULE.
4. Else extract numeric features.
5. Compute feature signature and check cache.
6. If cache hit and risk is medium/high, block with cached verdict.
7. If cache miss, call ai-engine POST /predict with features.
8. ai-engine computes risk using ML plus optional Claude judging.
9. ai-engine returns score and risk.
10. microshield-npm caches result and applies block or allow.
11. microshield-npm logs AI_BLOCK or AI_FAIL_OPEN when relevant.

## Reliability and Failure Policy

Current middleware policy:
- failOpen=true: allow traffic if ai-engine is down.
- failOpen=false: fail closed with HTTP 503.

Recommendations:
- Use health checks on ai-engine.
- Emit structured tracing IDs for cross-repo debugging.
- Track timeout rate, error rate, and risk distribution.

## Versioning Strategy

To avoid integration drift between repos:
- Maintain a shared contract doc for /predict schema.
- Version policy/model in ai-engine responses internally.
- Add contract tests in both repos.

Contract test cases to include:
- valid low response
- valid medium/high response
- malformed response
- timeout handling
- non-200 response handling

## Suggested Folder/Repo Layout

Example workspace:
- microshield-npm/
- ai-engine/

Suggested local flow:
1. Start ai-engine on localhost:8000.
2. Start Express app using microshield-npm with aiUrl set to ai-engine /predict.
3. Replay benign and malicious payloads.
4. Validate block/allow behavior and log output.

## Minimal ai-engine Express Stub

const express = require("express");
const app = express();
app.use(express.json());

app.post("/predict", (req, res) => {
  const f = req.body || {};
  const score = Math.min(1, (Number(f.specialChars || 0) / 20) + (Number(f.entropy || 0) / 10));
  const risk = score >= 0.7 ? "high" : score >= 0.4 ? "medium" : "low";
  res.json({ score, risk });
});

app.listen(8000, () => console.log("ai-engine listening on 8000"));

Use this stub only for local integration testing.
