import json
import os
import time
from datetime import datetime
from hashlib import sha256

from analyzer.analyzer import IncidentAnalyzer
from aws.sns import publish_ai_report_to_sns
from collector.collector import MasterCollector
from config import (
    AUTO_RESTART_FAILED_SERVICE_ONCE,
    DEFAULT_MONITOR_INTERVAL_SECONDS,
    MONITORING_MODE,
    SRE_STATE_FILE,
)
from executor.executor import ActionExecutor


def _load_notification_state() -> dict:
    if not os.path.exists(SRE_STATE_FILE):
        return {"last_status": "unknown", "recovery_notified": False}
    try:
        with open(SRE_STATE_FILE, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {"last_status": "unknown", "recovery_notified": False}


def _save_notification_state(state: dict) -> None:
    state_dir = os.path.dirname(SRE_STATE_FILE)
    if state_dir:
        os.makedirs(state_dir, exist_ok=True)
    with open(SRE_STATE_FILE, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)


def _has_issue(analysis_result: dict, evidence: dict) -> bool:
    failed_services = [
        name
        for name, details in evidence.get("service_diagnostics", {}).items()
        if details.get("status") == "failed"
    ]
    if failed_services:
        return True

    if analysis_result.get("recommended_action", "NOTIFY_ONLY") != "NOTIFY_ONLY":
        return True

    root_cause = str(analysis_result.get("root_cause", "")).lower()
    summary = str(analysis_result.get("summary", "")).lower()
    healthy_markers = ["no immediate", "normal", "healthy", "everything is fine", "no issue"]
    return not any(marker in root_cause or marker in summary for marker in healthy_markers)


def _issue_signature(analysis_result: dict, evidence: dict) -> str:
    """Build a stable comparison key for meaningful incident changes."""
    failed_services = sorted(
        name
        for name, details in evidence.get("service_diagnostics", {}).items()
        if details.get("status") == "failed"
    )
    issue = {
        "failed_services": failed_services,
        "recommended_action": analysis_result.get("recommended_action", "NOTIFY_ONLY"),
        "action_target": analysis_result.get("action_target", ""),
        "root_cause": str(analysis_result.get("root_cause", "")).strip().lower(),
    }
    return sha256(json.dumps(issue, sort_keys=True).encode("utf-8")).hexdigest()


def _should_publish_report(has_issue: bool, issue_signature: str | None = None) -> tuple[bool, str]:
    state = _load_notification_state()
    previous_status = state.get("last_status", "unknown")

    if has_issue:
        changed = previous_status != "issue" or state.get("issue_signature") != issue_signature
        state.update(
            {
                "last_status": "issue",
                "issue_signature": issue_signature,
                "recovery_notified": False,
            }
        )
        _save_notification_state(state)
        return changed, "incident"

    should_notify_recovery = previous_status == "issue" and not state.get("recovery_notified", False)
    state.update({"last_status": "healthy", "issue_signature": None, "recovery_notified": True})
    _save_notification_state(state)
    return should_notify_recovery, "recovery"


def run_sre_loop(auto_approve: bool = True) -> dict:
    print(f"🚀 Starting full-server AI monitoring cycle — {datetime.now().isoformat()}\n")

    print("[1/4] Collecting telemetry from the host operating system...")
    evidence = MasterCollector.collect_all(
        restart_failed_services_once=AUTO_RESTART_FAILED_SERVICE_ONCE,
    )

    print("[2/4] Dispatching evidence package to the AI analysis engine...")
    failed_services = [
        name
        for name, details in evidence.get("service_diagnostics", {}).items()
        if details.get("status") == "failed"
    ]
    
    cpu_util = evidence.get("cpu", {}).get("utilization_pct", 0.0)
    mem_util = evidence.get("memory", {}).get("virtual", {}).get("pct_used", 0.0)
    
    disk_util = 0.0
    partitions = evidence.get("disk", {}).get("partitions", [])
    for p in partitions:
        if p.get("mountpoint") == "/":
            disk_util = p.get("pct_used", 0.0)
            break
            
    if not failed_services and cpu_util < 90.0 and mem_util < 90.0 and disk_util < 90.0:
        print("🟢 System telemetry is healthy. Bypassing Gemini API key consumption.")
        analysis_result = {
            "summary": "System telemetry is within normal operating parameters.",
            "root_cause": "No issues detected. All monitored services and resource levels are healthy.",
            "supporting_evidence": [
                f"CPU utilization: {cpu_util}%",
                f"Memory utilization: {mem_util}%",
                f"Disk utilization: {disk_util}%"
            ],
            "recommended_action": "NOTIFY_ONLY",
            "action_target": ""
        }
    else:
        print("⚠️ Anomalous metrics or failed services detected. Querying Gemini AI SRE Analyzer...")
        analyzer = IncidentAnalyzer()
        analysis_result = analyzer.analyze_incident(evidence)

    print("\n================= AI SRE DIAGNOSTIC REPORT =================")
    print(f"SUMMARY            : {analysis_result.get('summary')}")
    print(f"ROOT CAUSE         : {analysis_result.get('root_cause')}")
    print(f"RECOMMENDED ACTION : {analysis_result.get('recommended_action')} -> target: ({analysis_result.get('action_target')})")
    print("============================================================\n")

    print("[3/4] Evaluating automation guardrail policy hooks...")
    recommended_action = analysis_result.get("recommended_action", "NOTIFY_ONLY")
    action_target = analysis_result.get("action_target", "")
    execution_result = ActionExecutor.execute(
        action=recommended_action,
        target=action_target,
        auto_approve=auto_approve,
    )
    print(f"Execution Output: {execution_result}")

    # Log execution in compliance DB
    if recommended_action != "NOTIFY_ONLY" and action_target:
        try:
            from admin.auth import log_remediation_audit
            action_desc = ""
            if recommended_action == "KILL_PROCESS":
                action_desc = f"kill -9 {action_target}"
            elif recommended_action == "RESTART_SERVICE":
                action_desc = f"systemctl restart {action_target}"
                
            if action_desc:
                log_remediation_audit(
                    operator="AI_SRE_AGENT",
                    command=action_desc,
                    exit_code=0 if execution_result.get("status") == "success" else 1,
                    stdout=execution_result.get("message", ""),
                    stderr=execution_result.get("error", ""),
                    success=(execution_result.get("status") == "success")
                )
        except Exception as db_err:
            print(f"DEBUG SRE Loop: Failed to write DB audit trace ({db_err})", flush=True)

    print("\n[4/4] Writing incident artifact trace log...")
    report = {
        "timestamp": datetime.now().isoformat(),
        "evidence_snapshot": evidence,
        "ai_analysis": analysis_result,
        "remediation_status": execution_result,
    }

    os.makedirs("reports", exist_ok=True)
    report_filename = f"reports/incident_{int(datetime.now().timestamp())}.json"
    with open(report_filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    print(f"💾 Diagnostic run completed. Artifact saved to: {report_filename}")

    has_issue = _has_issue(analysis_result, evidence)
    should_publish, notification_type = _should_publish_report(
        has_issue,
        _issue_signature(analysis_result, evidence) if has_issue else None,
    )
    if should_publish:
        publish_ai_report_to_sns(analysis_result, execution_result, notification_type)
    else:
        print("SNS notification suppressed because this incident was already reported and has not changed.")
    return report


def run_monitoring_loop(interval_seconds: int = DEFAULT_MONITOR_INTERVAL_SECONDS, iterations: int | None = None) -> None:
    iteration = 0
    while True:
        iteration += 1
        run_sre_loop()
        if iterations is not None and iteration >= iterations:
            break
        if MONITORING_MODE.lower() != "continuous":
            break
        print(f"⏳ Sleeping for {interval_seconds} seconds before next full-server monitoring cycle...\n")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    run_monitoring_loop()
