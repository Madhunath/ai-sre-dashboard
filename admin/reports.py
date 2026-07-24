import json
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from glob import glob


HIDDEN_REMEDIATION_STATUSES = {"skipped", "rejected"}


def _parse_report(path: str) -> dict | None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except Exception:
        return None

    analysis = report.get("ai_analysis", {})
    remediation = report.get("remediation_status", {})
    evidence = report.get("evidence_snapshot", {})
    failed_services = [
        name
        for name, details in evidence.get("service_diagnostics", {}).items()
        if details.get("status") == "failed"
    ]
    restarted_services = [
        name
        for name, details in evidence.get("service_diagnostics", {}).items()
        if details.get("restart_attempted")
    ]

    timestamp = report.get("timestamp", "")
    return {
        "path": path,
        "filename": os.path.basename(path),
        "timestamp": _format_india_time(timestamp),
        "timestamp_raw": timestamp,
        "summary": analysis.get("summary", ""),
        "root_cause": analysis.get("root_cause", ""),
        "recommended_action": analysis.get("recommended_action", "NOTIFY_ONLY"),
        "action_target": analysis.get("action_target", ""),
        "supporting_evidence": analysis.get("supporting_evidence", []),
        "remediation_status": remediation.get("status", ""),
        "remediation_message": remediation.get("message") or remediation.get("error", ""),
        "failed_services": failed_services,
        "restarted_services": restarted_services,
        "fresh_logs": _collect_fresh_logs(evidence),
        "disk_evidence": _collect_disk_evidence(evidence),
        "raw": report,
    }


def _collect_fresh_logs(evidence: dict) -> list[dict]:
    logs = []
    for service_name, details in evidence.get("service_diagnostics", {}).items():
        lines = details.get("fresh_error_logs") or details.get("journal_tail") or []
        if lines:
            logs.append({"source": service_name, "lines": lines[-20:]})

    system_errors = evidence.get("logs", {}).get("system_errors", [])
    if system_errors:
        logs.append({"source": "system", "lines": system_errors[-20:]})

    container_logs = evidence.get("container_logs", [])
    for container_log in container_logs:
        logs.append({
            "source": container_log["source"],
            "lines": container_log["lines"]
        })
    return logs



def _collect_disk_evidence(evidence: dict) -> list[dict]:
    return [
        {
            "source": f"disk:{partition.get('mountpoint', '/')}",
            "lines": [f"Usage: {partition.get('pct_used')}%"] + partition.get("largest_directories", []),
        }
        for partition in evidence.get("disk", {}).get("partitions", [])
        if partition.get("largest_directories")
    ]


_REPORTS_CACHE = {} # path -> (mtime, parsed_lightweight_dict)

def load_reports(limit: int = 100, lightweight: bool = True) -> list[dict]:
    global _REPORTS_CACHE
    reports = []
    paths = glob(os.path.join("reports", "incident_*.json"))

    def extract_epoch(p):
        base = os.path.basename(p)
        num_str = base.replace("incident_", "").replace(".json", "")
        try:
            return int(num_str)
        except ValueError:
            return 0

    paths.sort(key=extract_epoch, reverse=True)

    for path in paths:
        if len(reports) >= limit:
            break
            
        try:
            mtime = os.path.getmtime(path)
        except Exception:
            continue
            
        cached = _REPORTS_CACHE.get(path)
        if cached and cached[0] == mtime:
            parsed = cached[1]
        else:
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    raw_content = handle.read()
                if '"skipped"' in raw_content.lower() or '"rejected"' in raw_content.lower():
                    _REPORTS_CACHE[path] = (mtime, None)
                    continue
                report = json.loads(raw_content)
                
                remediation = report.get("remediation_status", {})
                status = remediation.get("status", "")
                analysis = report.get("ai_analysis", {})
                evidence = report.get("evidence_snapshot", {})
                timestamp = report.get("timestamp", "")
                
                parsed = {
                    "filename": os.path.basename(path),
                    "timestamp": _format_india_time(timestamp),
                    "summary": analysis.get("summary", ""),
                    "remediation_status": status,
                    "has_logs": len(_collect_fresh_logs(evidence)) > 0
                }
                _REPORTS_CACHE[path] = (mtime, parsed)
            except Exception:
                continue
                
        if parsed:
            reports.append(parsed)

    if not lightweight:
        full_reports = []
        for r in reports:
            p = os.path.join("reports", r["filename"])
            full_r = _parse_report(p)
            if full_r:
                full_reports.append(full_r)
        return full_reports

    return reports


def _format_india_time(timestamp: str) -> str:
    try:
        value = datetime.fromisoformat(timestamp)
        value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
        return value.astimezone(ZoneInfo("Asia/Kolkata")).strftime("%d %b %Y, %I:%M:%S %p IST")
    except (TypeError, ValueError):
        return timestamp


def available_log_sources() -> list[str]:
    return sorted({log["source"] for report in load_reports(lightweight=False) for log in report["fresh_logs"]})


def service_inventory() -> list[dict]:
    for report in load_reports(1, lightweight=False):
        return report["raw"].get("evidence_snapshot", {}).get("services", {}).get("service_inventory", [])
    return []


import re

def normalize_rbac_string(s: str) -> str:
    s = s.strip()
    if s.startswith("k8s:"):
        parts = s.split(":", 1)
        val = parts[1] if len(parts) > 1 else ""
        if not val or val == "*":
            return s
            
        slash_count = val.count("/")
        if slash_count == 1:
            ns, name = val.split("/", 1)
            return f"k8s:*/{ns}/pods/{name}"
        elif slash_count == 0:
            return f"k8s:*/default/pods/{val}"
            
    return s


def is_log_source_allowed(allowed_sources: list[str], source: str) -> bool:
    if "*" in allowed_sources or "*:*" in allowed_sources:
        return True
    
    source = normalize_rbac_string(source).lower()
    for pattern in allowed_sources:
        pattern = normalize_rbac_string(pattern).lower()
        if pattern == source:
            return True
            
        regex_pattern = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        try:
            if re.match(regex_pattern, source):
                return True
        except Exception:
            pass

        # Fallback check for service name keyword (e.g. pattern="nginx", source="docker:nginx")
        if ":" not in pattern and "/" not in pattern:
            if pattern in source:
                return True
    return False


def reports_for_sources(allowed_sources: list[str], limit: int = 100, lightweight: bool = True) -> list[dict]:
    """Return only log groups explicitly authorized for a viewer."""
    visible = []
    for report in load_reports(limit, lightweight=False):
        log_groups = [
            group for group in report["fresh_logs"]
            if is_log_source_allowed(allowed_sources, group["source"])
        ]
        if log_groups:
            if lightweight:
                visible.append({
                    "filename": report["filename"],
                    "timestamp": report["timestamp"],
                    "summary": report["summary"],
                    "remediation_status": report["remediation_status"],
                    "has_logs": len(log_groups) > 0
                })
            else:
                cloned = report.copy()
                cloned["fresh_logs"] = log_groups
                visible.append(cloned)
    return visible

