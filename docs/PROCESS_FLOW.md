# MicroShield Process Flow

This document describes the runtime request pipeline in microshield-npm.

## High-Level Pipeline

1. Incoming request enters middleware.
2. Rate limiter is applied.
3. Static security rules run.
4. Request features are extracted.
5. Learn mode shortcut (optional).
6. Cache lookup by feature signature.
7. AI prediction call on cache miss.
8. Decision layer applies block or allow.
9. Event logging persists suspicious/block events.

## Detailed Step-by-Step

## Step 1: Rate Limiting

The middleware first applies express-rate-limit to reduce abusive request bursts.

Default policy:
- windowMs: 60000
- max: 120

## Step 2: Static Rule Detection

Known attack patterns are checked before AI inference:
- Oversized body
- SQL injection strings
- XSS markers
- Path traversal tokens
- Command injection patterns
- Suspicious user-agents
- Content-type/body mismatch

If a static rule matches:
- Request is blocked immediately with HTTP 403.
- origin STATIC_RULE is logged.

## Step 3: Feature Extraction

The feature extractor builds numeric signals from request structure:
- pathLength
- bodySize
- queryParams
- specialChars
- entropy
- methodPOST

These features are used as AI input and cache key material.

## Step 4: Learn Mode

If mode is learn:
- Features are sent to aiClient.sendSample.
- Request continues without AI blocking.

Note: sendSample is currently a placeholder and can be extended later.

## Step 5: Cache Lookup

A deterministic signature is generated from features using SHA-256 (shortened).

If signature exists in cache:
- If cached risk is medium/high, block with HTTP 403.
- Otherwise allow request.

Cache settings:
- LRU max entries: 1000
- TTL: 5 minutes

## Step 6: AI Prediction Call

On cache miss, middleware calls aiUrl with timeout 3000 ms.

Expected response:
- score: number
- risk: string

If AI call fails:
- failOpen=true -> allow request and log AI_FAIL_OPEN
- failOpen=false -> return HTTP 503 Security engine unavailable

## Step 7: Decision Layer

After successful AI response:
- Cache result by signature.
- If risk includes medium or high, block with HTTP 403 and log AI_BLOCK.
- Else allow request.

## Step 8: Error Guardrail

Unexpected middleware errors are captured by logger.logError and request continues via next().

## Sequence Diagram (Text)

Client -> Express App
Express App -> MicroShield Middleware
MicroShield Middleware -> Rate Limiter
Rate Limiter -> MicroShield Middleware
MicroShield Middleware -> Static Rules
Static Rules -> MicroShield Middleware
MicroShield Middleware -> Feature Extractor
Feature Extractor -> MicroShield Middleware
MicroShield Middleware -> Cache Lookup
Cache Lookup -> MicroShield Middleware
MicroShield Middleware -> AI Engine (/predict)
AI Engine -> MicroShield Middleware
MicroShield Middleware -> Logger
MicroShield Middleware -> Express Route Handler
Express Route Handler -> Client

## Operational Notes

- Keep ai-engine response schema stable.
- Monitor false positive rate for medium risk blocking.
- Add replay tests for both benign and malicious payloads.
- Consider endpoint-specific policies in future versions.
