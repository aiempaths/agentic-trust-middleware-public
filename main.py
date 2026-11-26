import argparse
import glob
import hashlib
import json
import logging
import os
import sys
from collections import Counter
from pathlib import Path

import requests
from dotenv import load_dotenv


load_dotenv()

MIDDLEWARE_ROOT = Path(__file__).resolve().parent
if str(MIDDLEWARE_ROOT) not in sys.path:
    sys.path.insert(0, str(MIDDLEWARE_ROOT))

from core.ingestion.parser import TelemetryParser
from core.routing.audit_lifecycle import (
    LIFECYCLE_STATE_FILE,
    evaluate_lifecycle,
    load_lifecycle_profiles,
    load_lifecycle_state,
    save_lifecycle_state,
    update_lifecycle_state,
)
from core.routing.cop_router import ClassificationCopRouter
from core.routing.classification_guardrails import apply_classification_guard, evaluate_classification_guard
from core.transformation.markup_compiler import PromptMarkupCompiler, anomaly_score, build_evidence_card, severity_band_for_source
from core.transformation.report_renderer import build_digest, parse_structured_analysis, render_event, validate_analysis
from services.llm_client import LLMRequestDispatcher


DATA_ROOT = Path(os.getenv("AUDIT_DATA_ROOT", str(MIDDLEWARE_ROOT / "data")))
TARGET_DATA_DIR = Path(os.getenv("TARGET_DATA_DIR", str(DATA_ROOT / "analyzed")))
OUTPUT_AUDIT_DIR = Path(os.getenv("OUTPUT_AUDIT_DIR", str(DATA_ROOT / "audit_results")))
AUDIT_CHECKPOINT_FILE = Path(os.getenv("AUDIT_CHECKPOINT_FILE", str(OUTPUT_AUDIT_DIR / "audit_checkpoints.json")))
BRAIN_QUERY_URL = os.getenv("BRAIN_QUERY_URL", "http://localhost:5005/brain/query")
RUN_MODE = os.getenv("AUDIT_RUN_MODE", "live")
PROVENANCE_CONFIG_FILES = (
    "config/system_prompts.yaml",
    "config/source_thresholds.json",
    "config/audit_lifecycle_profiles.json",
    "config/classification_guardrails.json",
)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
LOGGER = logging.getLogger("agentic-trust-middleware")


def load_checkpoints():
    if not AUDIT_CHECKPOINT_FILE.exists():
        return {}
    try:
        state = json.loads(AUDIT_CHECKPOINT_FILE.read_text(encoding="utf-8"))
        return state if isinstance(state, dict) else {}
    except Exception as error:
        LOGGER.warning("Checkpoint file unreadable, starting fresh: %s", error)
        return {}


def save_checkpoints(checkpoints):
    AUDIT_CHECKPOINT_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = AUDIT_CHECKPOINT_FILE.with_suffix(AUDIT_CHECKPOINT_FILE.suffix + ".tmp")
    temporary.write_text(json.dumps(checkpoints, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(AUDIT_CHECKPOINT_FILE)


def checkpoint_entry(status, **fields):
    entry = {"status": status}
    entry.update(fields)
    return entry


def checkpoint_status(value):
    return value.get("status", "unknown") if isinstance(value, dict) else value


def config_fingerprint():
    digest = hashlib.sha256()
    for relative_path in PROVENANCE_CONFIG_FILES:
        config_path = MIDDLEWARE_ROOT / relative_path
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(config_path.read_bytes() if config_path.exists() else b"MISSING")
        digest.update(b"\0")
    return digest.hexdigest()[:16]


def decode_record(raw_line):
    try:
        return json.loads(raw_line)
    except Exception:
        return None


def record_identity(file_name, line_idx, raw_line, record):
    record_id = record.get("record_id") if isinstance(record, dict) else None
    if record_id:
        return f"{file_name}:{record_id}"
    digest = hashlib.sha256(raw_line.encode("utf-8")).hexdigest()[:16]
    return f"{file_name}:{line_idx}:{digest}"


def migrate_legacy_checkpoint(file_name, lines, checkpoints):
    marker_path = OUTPUT_AUDIT_DIR / f".{file_name}.done"
    if not marker_path.exists():
        return
    for line_idx, raw_line in enumerate(lines, 1):
        if not raw_line.strip():
            continue
        identity = record_identity(file_name, line_idx, raw_line.strip(), decode_record(raw_line.strip()))
        checkpoints.setdefault(identity, "legacy_marker")
    marker_path.unlink()
    LOGGER.info("Migrated legacy checkpoint for %s", file_name)


def query_brain(question: str, source_filter: str = None, n_results: int = 4, cache: dict = None):
    cache_key = (source_filter, question)
    if cache is not None and cache_key in cache:
        return cache[cache_key]

    payload = {"question": question, "source": source_filter, "n_results": n_results}
    try:
        response = requests.post(BRAIN_QUERY_URL, json=payload, timeout=12)
        if response.status_code == 200:
            context = response.json().get("context_used", [])
            if cache is not None:
                cache[cache_key] = context
            return context
        LOGGER.warning("Brain query returned HTTP %s", response.status_code)
    except Exception as error:
        LOGGER.warning("Brain query failed for source %s: %s", source_filter, error)
    return []


def should_escalate(result, warnings, expected_severity, regime_shift):
    if not result.get("structured"):
        return True
    joined = " ".join(warnings).lower()
    hard_markers = (
        "disagrees",
        "valid json",
        "not grounded",
        "unknown evidence ids",
        "no evidence_refs",
        "no primary hypothesis",
        "no alternative explanations",
        "no disconfirming evidence",
        "duplicates drift_summary",
        "no valid uncertainty level",
        "critical language",
        "significant language",
        "downgraded elevated severity",
        "near-zero baseline despite",
        "claimed coupling",
        "normalcy semantics",
        "did not name source",
        "implausible percent delta",
        "ambiguous high-confidence language",
        "absolute certainty language",
        "no valid classification",
        "no classification basis",
        "exact source token",
        "unsupported real event",
        "insufficient evidence",
    )
    return any(marker in joined for marker in hard_markers)


def build_repair_request(system_instruction, populated_payload, warnings, expected_severity, source):
    checklist = "\n".join(f"- {warning}" for warning in warnings) or "- none"
    repair_system = (
        system_instruction.strip()
        + "\n\nREPAIR MODE:\n"
        + "A previous draft failed the checks below. Return a corrected JSON object with the same contract.\n"
        + f"Keep severity exactly {expected_severity}. Write the exact source token `{source}` verbatim in physical_assessment, primary_hypothesis, drift_summary, and verdict; paraphrases are rejected. Return one of the allowed classifications with a clear classification_basis. Do not repeat any listed error.\n"
    )
    repair_payload = (
        populated_payload.strip()
        + "\n\n[VALIDATION WARNINGS FROM PREVIOUS DRAFT]\n"
        + checklist
    )
    return repair_system, repair_payload


def execute_event_driven_pipeline(force: bool = False, max_events: int = None):
    print("[*] Initializing Event-Driven Topological Co-Processor Pipeline...")
    OUTPUT_AUDIT_DIR.mkdir(parents=True, exist_ok=True)

    if not TARGET_DATA_DIR.exists():
        print(f"[!] Target directory does not exist: {TARGET_DATA_DIR}")
        return

    log_files = glob.glob(os.path.join(TARGET_DATA_DIR, "*.*"))
    if not log_files:
        print("[-] No analyzed log files found.")
        return

    parser = TelemetryParser()
    router = ClassificationCopRouter()
    compiler = PromptMarkupCompiler()
    dispatcher = LLMRequestDispatcher()
    brain_cache = {}
    checkpoints = load_checkpoints()
    lifecycle_config = load_lifecycle_profiles()
    lifecycle_states = load_lifecycle_state(OUTPUT_AUDIT_DIR / LIFECYCLE_STATE_FILE)
    config_hash = config_fingerprint()
    action_counts = Counter()

    total_inspected = 0
    total_skipped = 0
    total_routed_to_ai = 0
    total_bypassed = 0
    total_dispatched = 0
    total_escalated = 0
    total_structured = 0
    total_parse_failures = 0

    for file_path in log_files:
        if max_events is not None and total_routed_to_ai >= max_events:
            break
        file_name = os.path.basename(file_path)
        with open(file_path, "r", encoding="utf-8", errors="ignore") as stream:
            lines = stream.readlines()

        migrate_legacy_checkpoint(file_name, lines, checkpoints)

        source_name = Path(file_name).stem.replace("_analysis_history", "").replace("_audit_report", "")
        report_path = OUTPUT_AUDIT_DIR / f"audit_report_{Path(file_name).stem}.txt"
        append_report = report_path.exists() and not force

        print(f"\n[+] Processing Stream: {file_name}")

        with open(report_path, "a" if append_report else "w", encoding="utf-8") as report_out:
            if not append_report:
                report_out.write(f"=== TOPOLOGICAL PHASE SHIFT AUDIT: {file_name} ===\n\n")

            for line_idx, raw_line in enumerate(lines, 1):
                if max_events is not None and total_routed_to_ai >= max_events:
                    break
                clean_line = raw_line.strip()
                if not clean_line:
                    continue

                identity = record_identity(file_name, line_idx, clean_line, decode_record(clean_line))
                if identity in checkpoints and not force:
                    total_skipped += 1
                    continue

                total_inspected += 1

                evidence_hash = hashlib.sha256(clean_line.encode("utf-8")).hexdigest()[:16]
                packet = parser.parse_line(clean_line)
                if not packet:
                    total_parse_failures += 1
                    checkpoints[identity] = checkpoint_entry(
                        "parse_failure",
                        source=source_name,
                        evidence_sha256=evidence_hash,
                        run_mode=RUN_MODE,
                    )
                    continue

                route_action, trust_tier = router.determine_route(packet)

                if route_action == "BYPASS_TO_ALERT_BUS":
                    total_bypassed += 1
                    checkpoints[identity] = checkpoint_entry(
                        "bypass",
                        source=str(packet.source_domain),
                        evidence_sha256=evidence_hash,
                        run_mode=RUN_MODE,
                        trust_tier=trust_tier,
                    )
                    print(f"  [BYPASS ALERT] Line {line_idx} | Tier: {trust_tier} | Conf: {packet.confidence}")
                    report_out.write(f"[LINE {line_idx}] BYPASS ALERT | Tier: {trust_tier} | Conf: {packet.confidence}\n")
                    report_out.write(f"Route Action: {route_action} (Skipped LLM Inference)\n")
                    report_out.write("-" * 80 + "\n")
                    continue

                total_routed_to_ai += 1
                anomaly_value = anomaly_score(packet.confidence)
                expected_severity = severity_band_for_source(anomaly_value, packet.source_domain)
                print(f"  [AI AUDIT] Line {line_idx} | Tier: {trust_tier} | Normalcy: {packet.confidence:.4f} | Anomaly: {anomaly_value:.4f} | Severity: {expected_severity}")

                lifecycle_source = str(packet.source_domain) or source_name
                provisional_lifecycle = evaluate_lifecycle(
                    lifecycle_states.get(lifecycle_source),
                    lifecycle_source,
                    expected_severity,
                    anomaly_value,
                    classification="uncertain",
                    evidence_quality="unknown",
                    regime_shift=packet.regime_shift,
                    coupled_streams=packet.coupled_streams,
                    config=lifecycle_config,
                )

                brain_question = f"Topological transition patterns for {source_name} under tier {trust_tier}"
                brain_context = query_brain(
                    brain_question,
                    source_filter=source_name,
                    n_results=3,
                    cache=brain_cache,
                )

                evidence_card = build_evidence_card(packet, trust_tier, brain_context, provisional_lifecycle)
                system_instruction, populated_payload = compiler.compile_payload(
                    packet,
                    trust_tier,
                    brain_context,
                    provisional_lifecycle,
                )

                response = dispatcher.dispatch_agentic_audit(system_instruction, populated_payload, require_json=True)

                if response.get("status") in ["SUCCESS", "SIMULATED"]:
                    total_dispatched += 1
                    raw_analysis = response.get("analysis") or ""
                    result = parse_structured_analysis(raw_analysis)
                    final_lifecycle = evaluate_lifecycle(
                        lifecycle_states.get(lifecycle_source),
                        lifecycle_source,
                        expected_severity,
                        anomaly_value,
                        classification=result.get("classification") or "uncertain",
                        evidence_quality=result.get("evidence_quality") or "unknown",
                        regime_shift=packet.regime_shift,
                        coupled_streams=packet.coupled_streams,
                        config=lifecycle_config,
                    )
                    warnings = validate_analysis(
                        result,
                        expected_severity,
                        packet.regime_shift,
                        raw_analysis,
                        evidence_card["evidence_ids"],
                        evidence_card["saturation"],
                        packet.source_domain,
                        evidence_card["pct_note"],
                            bool(packet.coupled_streams),
                            anomaly=anomaly_value,
                        )


                    if dispatcher.escalation_enabled and should_escalate(result, warnings, expected_severity, packet.regime_shift):
                        total_escalated += 1
                        repair_system, repair_payload = build_repair_request(
                            system_instruction,
                            populated_payload,
                            warnings,
                            expected_severity,
                            packet.source_domain,
                        )
                        escalated = dispatcher.dispatch_agentic_audit(
                            repair_system,
                            repair_payload,
                            model=dispatcher.escalation_model,
                            max_tokens=dispatcher.max_tokens + 400,
                            require_json=True,
                        )
                        if escalated.get("status") in ["SUCCESS", "SIMULATED"]:
                            escalated_raw = escalated.get("analysis") or ""
                            escalated_result = parse_structured_analysis(escalated_raw)
                            escalated_warnings = validate_analysis(
                                escalated_result,
                                expected_severity,
                                packet.regime_shift,
                                escalated_raw,
                                evidence_card["evidence_ids"],
                                evidence_card["saturation"],
                                packet.source_domain,
                                evidence_card["pct_note"],
                                bool(packet.coupled_streams),
                                anomaly=anomaly_value,
                            )
                            if escalated_result["structured"] and (
                                not result["structured"] or len(escalated_warnings) <= len(warnings)
                            ):
                                response = escalated
                                result = escalated_result
                                warnings = escalated_warnings
                                raw_analysis = escalated_raw
                                final_lifecycle = evaluate_lifecycle(
                                    lifecycle_states.get(lifecycle_source),
                                    lifecycle_source,
                                    expected_severity,
                                    anomaly_value,
                                    classification=result.get("classification") or "uncertain",
                                    evidence_quality=result.get("evidence_quality") or "unknown",
                                    regime_shift=packet.regime_shift,
                                    coupled_streams=packet.coupled_streams,
                                    config=lifecycle_config,
                                )
                            else:
                                LOGGER.info("Escalation output was not better on line %s; kept primary output", line_idx)
                        else:
                            LOGGER.warning("Escalation failed on line %s: %s", line_idx, escalated.get("error"))

                    classification_guard = evaluate_classification_guard(
                        lifecycle_source,
                        result.get("classification") or "",
                        anomaly_value,
                        expected_severity,
                        bool(packet.regime_shift),
                        bool(packet.coupled_streams),
                        result.get("evidence_quality") or "",
                    )
                    result = apply_classification_guard(result, classification_guard)

                    if response.get("truncated"):
                        warnings.append("model output was truncated by token limit")

                    if not result["structured"]:
                        LOGGER.error("Unusable non-JSON audit on line %s; leaving record uncheckpointed for retry", line_idx)
                        continue

                    if result["structured"]:
                        total_structured += 1

                    lifecycle_states = update_lifecycle_state(
                        lifecycle_states,
                        final_lifecycle,
                        evidence_hash,
                    )
                    action_counts[final_lifecycle["action"]] += 1
                    provenance = {
                        "mode": RUN_MODE,
                        "execution": "local",
                        "model": response.get("model") or "unknown",
                        "request_sha256": str(response.get("request_sha256") or "unknown")[:16],
                        "config_sha256": config_hash,
                        "evidence_sha256": evidence_hash,
                        "attempts": response.get("attempts") or "unknown",
                    }
                    checkpoints[identity] = checkpoint_entry(
                        "ai_audited",
                        source=lifecycle_source,
                        evidence_sha256=evidence_hash,
                        run_mode=RUN_MODE,
                        model=provenance["model"],
                        request_sha256=provenance["request_sha256"],
                        config_sha256=config_hash,
                        classification=result.get("classification"),
                        operational_action=final_lifecycle["action"],
                        warnings=warnings,
                    )
                    report_out.write(render_event(
                        {
                            "line": line_idx,
                            "source": lifecycle_source,
                            "tier": trust_tier,
                            "normalcy": packet.confidence,
                            "anomaly": anomaly_value,
                            "severity": expected_severity,
                            "regime_shift": packet.regime_shift,
                            "operational_action": final_lifecycle["action"],
                            "lifecycle": final_lifecycle,
                            "provenance": provenance,
                        },
                        result,
                        warnings,
                    ))
                else:
                    LOGGER.error("LLM dispatch failed on line %s: %s", line_idx, response.get("error"))

        save_checkpoints(checkpoints)
        save_lifecycle_state(lifecycle_states, OUTPUT_AUDIT_DIR / LIFECYCLE_STATE_FILE)
        print(f"[OK] Report compiled: {report_path.name}")

    digest_path = build_digest(OUTPUT_AUDIT_DIR)
    print(f"[OK] Digest compiled: {digest_path.name}")

    summary = {
        "run_mode": RUN_MODE,
        "model": getattr(dispatcher, "model_name", "unknown"),
        "config_sha256": config_hash,
        "total_lines_seen": total_inspected + total_skipped,
        "skipped_by_checkpoint": total_skipped,
        "newly_inspected": total_inspected,
        "parse_failures": total_parse_failures,
        "bypassed_to_alert_bus": total_bypassed,
        "routed_to_ai_agent": total_routed_to_ai,
        "dispatched_to_ollama": total_dispatched,
        "escalated_dispatches": total_escalated,
        "structured_audits": total_structured,
        "operational_actions": dict(sorted(action_counts.items())),
        "checkpoint_statuses": dict(sorted(Counter(checkpoint_status(value) for value in checkpoints.values()).items())),
        "event_limit_reached": max_events is not None and total_routed_to_ai >= max_events,
    }
    (OUTPUT_AUDIT_DIR / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n" + "=" * 70)
    print("[OK] Event-Driven Run Complete")
    print(f"    Lines Skipped (checkpoint): {total_skipped}")
    print(f"    New Lines Inspected       : {total_inspected}")
    print(f"    Parse Failures            : {total_parse_failures}")
    print(f"    Bypassed to Alert Bus     : {total_bypassed}")
    print(f"    Routed to AI Agent        : {total_routed_to_ai}")
    print(f"    Dispatched to Ollama      : {total_dispatched}")
    print(f"    Escalated Dispatches      : {total_escalated}")
    print(f"    Structured audits         : {total_structured}")
    print("=" * 70)


if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser(description="Agentic trust middleware audit pipeline")
    argument_parser.add_argument("--force", action="store_true", help="Re-audit all records, ignoring checkpoints")
    argument_parser.add_argument("--max-events", type=int, default=None, help="Maximum AI audit events per run")
    args = argument_parser.parse_args()
    try:
        execute_event_driven_pipeline(force=args.force, max_events=args.max_events)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
