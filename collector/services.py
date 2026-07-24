import os
import shutil
import subprocess


class ServiceCollector:
    @staticmethod
    def collect() -> dict:
        services = {
            "failed_services": [],
            "running_services": [],
            "all_services": [],
            "service_details": {},
            "status": "success",
        }

        try:
            systemctl = shutil.which("systemctl")
            if systemctl:
                failed = subprocess.run(
                    [systemctl, "--failed", "--no-pager"],
                    capture_output=True,
                    text=True,
                    timeout=8,
                )
                running = subprocess.run(
                    [systemctl, "list-units", "--type=service", "--all", "--no-pager"],
                    capture_output=True,
                    text=True,
                    timeout=8,
                )

                services["failed_services"] = [line.strip() for line in failed.stdout.splitlines() if line.strip()]
                services["all_services"] = [line.strip() for line in running.stdout.splitlines() if line.strip()]
                services["service_inventory"] = [
                    {"name": parts[0], "status": parts[3] if len(parts) > 3 else "unknown"}
                    for line in running.stdout.splitlines()[1:]
                    if (parts := line.split()) and parts[0].endswith(".service")
                ]
                services["running_services"] = [
                    line.strip()
                    for line in running.stdout.splitlines()
                    if "running" in line.lower() and "service" not in line.lower()
                ]

                for unit_name in ["nginx", "mysql", "ssh", "snapd", "docker"]:
                    service_status = subprocess.run(
                        [systemctl, "is-active", f"{unit_name}.service"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    service_enabled = subprocess.run(
                        [systemctl, "is-enabled", f"{unit_name}.service"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    services["service_details"][unit_name] = {
                        "active": service_status.stdout.strip(),
                        "enabled": service_enabled.stdout.strip(),
                    }

            elif os.name == "nt":
                services["failed_services"] = ["Windows service inspection is not available in this environment."]
            else:
                services["failed_services"] = ["systemctl is not available on this host."]
        except Exception as e:
            services.update({"status": "partial_error", "error": str(e)})

        return services
