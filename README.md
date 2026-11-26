# Agentic Trust Middleware

Trust infrastructure for telemetry-driven decisions.

This sanitized public package shows the architecture and evaluation method without deployment data, credentials, logs, holdout labels, or private service configuration.

## What it does

- Ingests normalized telemetry packets.
- Routes low-risk records away from the LLM.
- Builds evidence cards and deterministic prompt contracts.
- Treats LLM output as untrusted and validates it.
- Enforces exact source naming, classification rules, provenance, and lifecycle state.
- Renders auditable HOLD/WATCH/ACT reports.
- Scores replay cases with baseline-aware metrics.

## Public boundary

Included: middleware code, sanitized configs, tests, replay scorer, synthetic cases, architecture notes.

Not included: `.env`, real telemetry, checkpoints, live reports, holdout labels, logs, virtual environments, or service credentials.

## Setup

```powershell
python -m pip install -r requirements.txt
Copy-Item .env.example .env
$env:PYTHONUTF8='1'
python -m pytest -q
```

## Development evidence

Dev-only replay showed source naming 19/19, classification 18/19, average 6.05/7, and 94.74% accuracy versus 57.89% majority baseline. These are dev results with provisional labels, not locked holdout claims.

## Safety note

This system recommends; it does not act autonomously. Coupled-stream context is geometric similarity, not causal proof.
