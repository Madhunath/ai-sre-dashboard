import os
import subprocess

from config import DEFAULT_LOG_LINES


class LogCollector:
    @staticmethod
    def collect(since: str | None = None) -> dict:
        collected_logs = {
            "system_errors": [],
            "log_files": [],
            "since": since,
            "status": "success",
        }

        try:
            command = ["journalctl", "-p", "3", "-n", str(DEFAULT_LOG_LINES), "--no-pager"]
            if since:
                command = ["journalctl", "-p", "3", "--since", since, "--no-pager"]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=8,
            )
            collected_logs["system_errors"] = result.stdout.splitlines()[-DEFAULT_LOG_LINES:]
        except Exception as e:
            collected_logs["system_errors"] = ["Could not fetch journalctl logs."]
            collected_logs["status"] = "partial_error"
            collected_logs["error"] = str(e)

        if since:
            return collected_logs

        log_paths = [
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/nginx/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log.1",
        ]

        for path in log_paths:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    lines = handle.readlines()[-DEFAULT_LOG_LINES:]
                collected_logs["log_files"].append({
                    "path": path,
                    "lines": [line.rstrip() for line in lines],
                })

        return collected_logs
