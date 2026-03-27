# Session Notes - 2026-03-22

## Scope
- Hardened middleware to better detect automated attack tools and improve decision safety.
- Added clearer source attribution and static rule metadata in block responses/logs.

## Changes Made (microshield-npm)
- Updated `lib/staticRules.js`:
  - Added multi-round decode for encoded payloads.
  - Expanded SQLi/XSS/path traversal/command injection signatures.
  - Added suspicious user-agent detection for automation/scanners, including:
    - `sqlmap`, `hydra`, `ffuf`, `wfuzz`, `gobuster`, `dirbuster`, `nmap`, `nikto`, `masscan`, `zgrab`
  - Added reconnaissance path detection, including:
    - `/.env`, `/.git/config`, `/wp-admin`, `/wp-login.php`, `/phpmyadmin`, `/server-status`, `/actuator`
  - Static rule detection now returns metadata object:
    - `matched`, `ruleId`, `message`, `matchedValue`
- Updated `lib/aiClient.js`:
  - Strict AI response validation (`score` numeric, risk normalized to `low|medium|high`).
  - Invalid AI schema now throws error (no silent low-risk fallback).
- Updated `index.js`:
  - Static rule step now logs/returns `ruleId` when blocked.
  - AI cached and live risk checks now use strict normalized risk enums.
  - Added risk normalization helper for consistent handling.

## Current Decision Flow
1. Rate limit
2. Static rules
3. Feature extraction
4. Learn mode (optional)
5. Cache lookup
6. AI call
7. Decision layer

## Source Attribution
- `STATIC_RULE` => blocked by static signatures
- `AI_ENGINE` => blocked/allowed by AI decision path
- `AI_FAIL_OPEN` => AI unavailable and fail-open allowed request

## Test Expectations
- Static scanner payloads should block with `source=STATIC_RULE` and `ruleId`.
- Non-static suspicious payloads should proceed to AI and block with `source=AI_ENGINE` when risk is medium/high.

## Known Gaps
- AI engine still returns raw anomaly score and title-cased risk unless updated in AI repo.
- For publish-ready metrics, add benchmark matrix and false-positive tracking.

## Quick Restart Checklist
1. Start AI API (`microshield-ai-engine`) on `127.0.0.1:8000`.
2. Start `testapp.js` in `microshield-npm`.
3. Run full tester from AI repo in `both` mode.
4. Verify block source headers and rule IDs in responses/logs.

## Suggested Commit Messages
- `chore(docs): add session notes for 2026-03-22`
- `feat(security): harden static bot/scanner detection and strict AI validation`
