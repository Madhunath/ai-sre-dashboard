import subprocess
import shutil

class ContainerLogCollector:
    @staticmethod
    def _is_cli_available(cli_name: str) -> bool:
        return shutil.which(cli_name) is not None

    @staticmethod
    def collect_docker_logs(limit_containers: int = 10, tail_lines: int = 80) -> list[dict]:
        logs = []
        if not ContainerLogCollector._is_cli_available("docker"):
            return logs

        try:
            # List running container names
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return logs

            container_names = [name.strip() for name in result.stdout.splitlines() if name.strip()][:limit_containers]

            for name in container_names:
                try:
                    log_result = subprocess.run(
                        ["docker", "logs", "--tail", str(tail_lines), name],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    # Merge stdout and stderr lines
                    lines = log_result.stdout.splitlines() + log_result.stderr.splitlines()
                    # Filter empty lines
                    lines = [line.rstrip() for line in lines if line.strip()]
                    
                    logs.append({
                        "source": f"docker:{name}",
                        "lines": lines[-tail_lines:]
                    })
                except subprocess.TimeoutExpired:
                    logs.append({
                        "source": f"docker:{name}",
                        "lines": ["Timeout expired while fetching logs for container."]
                    })
                except Exception as e:
                    logs.append({
                        "source": f"docker:{name}",
                        "lines": [f"Failed to fetch logs: {e}"]
                    })
        except Exception:
            pass  # Fail silently to avoid interrupting the SRE loop
        return logs

    @staticmethod
    def collect_kubernetes_logs(limit_pods: int = 10, tail_lines: int = 80) -> list[dict]:
        logs = []
        if not ContainerLogCollector._is_cli_available("kubectl"):
            return logs

        try:
            # Fetch pods in all namespaces: namespace, pod_name
            result = subprocess.run(
                ["kubectl", "get", "pods", "--all-namespaces", "--no-headers", "-o", "custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return logs

            pod_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()][:limit_pods]

            for pod_line in pod_lines:
                parts = pod_line.split()
                if len(parts) < 2:
                    continue
                namespace, pod_name = parts[0], parts[1]

                try:
                    log_result = subprocess.run(
                        ["kubectl", "logs", "--tail", str(tail_lines), "--all-containers=true", "-n", namespace, pod_name],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    lines = log_result.stdout.splitlines() + log_result.stderr.splitlines()
                    lines = [line.rstrip() for line in lines if line.strip()]

                    logs.append({
                        "source": f"k8s:{namespace}/{pod_name}",
                        "lines": lines[-tail_lines:]
                    })
                except subprocess.TimeoutExpired:
                    logs.append({
                        "source": f"k8s:{namespace}/{pod_name}",
                        "lines": ["Timeout expired while fetching pod logs."]
                    })
                except Exception as e:
                    logs.append({
                        "source": f"k8s:{namespace}/{pod_name}",
                        "lines": [f"Failed to fetch logs: {e}"]
                    })
        except Exception:
            pass  # Fail silently to avoid interrupting the SRE loop
        return logs

    @classmethod
    def collect_all(cls) -> list[dict]:
        logs = []
        logs.extend(cls.collect_docker_logs())
        logs.extend(cls.collect_kubernetes_logs())
        return logs
