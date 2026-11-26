# Architecture

Flow:

`normalized telemetry -> parser -> router -> evidence compiler -> LLM gateway -> validator/guardrails -> lifecycle renderer -> replay evaluation`

## Modules

- `core/ingestion/`: parses normalized telemetry into a common packet schema.
- `core/routing/`: routing rules, trust tiers, lifecycle states, and classification guardrails.
- `core/transformation/`: evidence cards, prompt compilation, output parsing, validation, rendering, and digest generation.
- `services/`: LLM dispatcher with retries, timeouts, JSON mode, and request fingerprints.
- `config/`: prompts, thresholds, lifecycle policies, and guardrail policy.
- `eval/`: replay scoring, baseline-aware metrics, and synthetic example cases.
- `tests/`: regression tests for parser, router, renderer, guardrails, lifecycle, and scoring.
- root scripts: optional operational helpers; require environment variables for local paths.

## Control principle

The LLM proposes interpretations. Deterministic code owns severity, source identity, validity checks, provenance, and lifecycle state.
