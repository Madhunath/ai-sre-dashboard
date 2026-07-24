import re


class IncidentClassifier:
    @staticmethod
    def classify_service_failure(service_name: str, service_details: dict, logs: dict) -> dict:
        fresh_logs = service_details.get("fresh_error_logs", [])
        journal_tail = "\n".join(fresh_logs or service_details.get("journal_tail", []))
        log_text = ""
        if not fresh_logs:
            log_text = "\n".join(
                [line for entry in logs.get("log_files", []) for line in entry.get("lines", [])]
            )
        combined_text = "\n".join([journal_tail, log_text]).lower()

        indicators = []
        if re.search(r"(address already in use|bind\(|port .* in use|eaddrinuse)", combined_text):
            indicators.append("Port conflict or address already in use")
        if re.search(r"(permission denied|access denied|forbidden)", combined_text):
            indicators.append("Permission or access issue")
        if re.search(r"(no such file|not found|missing)", combined_text):
            indicators.append("Missing file or configuration path")
        if re.search(r"(emerg|fatal|syntax error|configuration file)", combined_text):
            indicators.append("Configuration syntax or parsing error")
        if re.search(r"(out of memory|oom|killed)", combined_text):
            indicators.append("Out-of-memory or process termination")
        if re.search(r"(disk full|no space|quota exceeded)", combined_text):
            indicators.append("Disk space exhaustion")
        if re.search(r"(failed to start|failed to load|cannot start)", combined_text):
            indicators.append("Startup failure")

        if not indicators:
            indicators.append("Generic service startup or runtime failure")

        return {
            "service_name": service_name,
            "likely_cause": indicators[0],
            "evidence_indicators": indicators,
            "service_active": service_details.get("active"),
            "service_enabled": service_details.get("enabled"),
        }
