import os
import signal
import subprocess
import psutil

from config import AUTO_KILL_PROCESS


class ActionExecutor:
    @staticmethod
    def execute(action: str, target: str, auto_approve: bool = True) -> dict:
        if action == "NOTIFY_ONLY" or not target:
            return {"status": "notified", "message": "Incident recorded and notification policy applied."}

        print(f"\n⚠️ [GUARDRAIL WARNING] AI requested execution: Mode={action} on Target={target}")

        if not auto_approve:
            return {"status": "rejected", "message": "Execution requires explicit approval."}

        try:
            if action == "KILL_PROCESS":
                if not AUTO_KILL_PROCESS:
                    return {
                        "status": "notified",
                        "message": "Process termination is disabled (AUTO_KILL_PROCESS=false).",
                    }

                target_pid = int(target)
                current_pid = os.getpid()

                if target_pid == current_pid:
                    return {"status": "failed", "message": "Refusing to terminate the active agent process."}
                if target_pid in [0, 1]:
                    return {"status": "failed", "message": "Refusing to terminate the system init process."}

                try:
                    proc = psutil.Process(target_pid)
                except psutil.NoSuchProcess:
                    return {"status": "failed", "error": f"Process ID {target_pid} vanished before check."}

                process_name = proc.name()
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except psutil.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                return {
                    "status": "success",
                    "message": f"Terminated process '{process_name}' (PID {target_pid}).",
                }

            elif action == "RESTART_SERVICE":
                if target.lower() in ["ssh", "sshd", "systemd", "networking", "mysql", "mysql.service", "nginx", "nginx.service"]:
                    return {"status": "rejected", "message": "Guardrail blocked restarting core system tools or database/web services automatically."}

                subprocess.run(["sudo", "systemctl", "restart", target], check=True)
                return {"status": "success", "message": f"Successfully executed systemctl restart on {target} autonomously."}

            return {"status": "unknown_action", "message": f"Action {action} not mapped."}
        except Exception as e:
            return {"status": "failed", "error": str(e)}
