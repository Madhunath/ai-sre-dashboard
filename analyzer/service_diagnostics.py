import os
import subprocess
from datetime import datetime, timezone

from config import AUTO_RESTART_FAILED_SERVICE_ONCE


class ServiceDiagnostics:
    COMMON_SERVICE_NAMES = [
        "nginx",
        "mysql",
        "mariadb",
        "postgresql",
        "ssh",
        "sshd",
        "snapd",
        "docker",
        "apache2",
        "redis",
        "mongodb",
        "prometheus",
        "grafana",
        "node",
    ]

    @staticmethod
    def _service_unit(service_name: str) -> str:
        return service_name if service_name.endswith(".service") else f"{service_name}.service"

    @staticmethod
    def _read_journal(unit_name: str, since: str | None = None) -> list[str]:
        command = ["journalctl", "-u", unit_name, "-n", "20", "--no-pager"]
        if since:
            command = ["journalctl", "-u", unit_name, "--since", since, "--no-pager"]

        journal = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=8,
        )
        return journal.stdout.splitlines()[-20:]

    @staticmethod
    def _read_load_state(unit_name: str) -> str:
        result = subprocess.run(
            ["systemctl", "show", unit_name, "--property=LoadState", "--value"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip()

    @staticmethod
    def inspect_service(
        service_name: str,
        restart_once: bool = AUTO_RESTART_FAILED_SERVICE_ONCE,
        since: str | None = None,
    ) -> dict:
        unit_name = ServiceDiagnostics._service_unit(service_name)
        details = {
            "service_name": service_name,
            "unit_name": unit_name,
            "status": "unknown",
            "active": None,
            "enabled": None,
            "journal_tail": [],
            "fresh_error_logs": [],
            "restart_attempted": False,
            "restart_result": None,
            "restart_checked_since": None,
            "config_files": [],
        }

        if os.name == "nt":
            return details

        try:
            details["load_state"] = ServiceDiagnostics._read_load_state(unit_name)
            if details["load_state"] == "not-found":
                details["status"] = "not_installed"
                return details

            systemctl = subprocess.run(
                ["systemctl", "is-active", unit_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            enabled = subprocess.run(
                ["systemctl", "is-enabled", unit_name],
                capture_output=True,
                text=True,
                timeout=5,
            )

            details["active"] = systemctl.stdout.strip()
            details["enabled"] = enabled.stdout.strip()
            details["journal_tail"] = ServiceDiagnostics._read_journal(unit_name, since)[-10:]
            details["status"] = "ok" if systemctl.returncode == 0 else "failed"

            if details["status"] == "failed" and restart_once:
                since = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                details["restart_attempted"] = True
                details["restart_checked_since"] = since
                restart = subprocess.run(
                    ["sudo", "systemctl", "restart", unit_name],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                recheck = subprocess.run(
                    ["systemctl", "is-active", unit_name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                details["restart_result"] = {
                    "returncode": restart.returncode,
                    "stdout": restart.stdout.strip(),
                    "stderr": restart.stderr.strip(),
                    "active_after_restart": recheck.stdout.strip(),
                }
                details["active"] = recheck.stdout.strip()
                details["status"] = "ok" if recheck.returncode == 0 else "failed"
                details["fresh_error_logs"] = ServiceDiagnostics._read_journal(unit_name, since)
                details["journal_tail"] = []
        except Exception as exc:
            details["status"] = "error"
            details["error"] = str(exc)

        config_candidates = [
            f"/etc/{service_name}/{service_name}.conf",
            f"/etc/{service_name}/conf.d",
            f"/etc/nginx/nginx.conf",
            f"/etc/nginx/sites-enabled/default",
            f"/etc/mysql/mysql.conf.d/mysqld.cnf",
            f"/etc/postgresql/postgresql.conf",
            f"/etc/redis/redis.conf",
            f"/etc/mongodb/mongod.conf",
            f"/etc/apache2/apache2.conf",
        ]
        for path in config_candidates:
            if os.path.exists(path):
                details["config_files"].append(path)

        return details

    @staticmethod
    def inspect_common_services(
        restart_once: bool = AUTO_RESTART_FAILED_SERVICE_ONCE,
        since: str | None = None,
    ) -> dict:
        return {
            service: ServiceDiagnostics.inspect_service(
                service,
                restart_once=restart_once,
                since=since,
            )
            for service in ServiceDiagnostics.COMMON_SERVICE_NAMES
        }
