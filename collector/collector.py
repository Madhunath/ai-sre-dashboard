from analyzer.incident_classifier import IncidentClassifier
from analyzer.service_diagnostics import ServiceDiagnostics
from datetime import datetime, timezone
from collector.cpu import CPUCollector
from collector.disk import DiskCollector
from collector.logs import LogCollector
from collector.memory import MemoryCollector
from collector.network import NetworkCollector
from collector.process import ProcessCollector
from collector.services import ServiceCollector
from collector.containers import ContainerLogCollector
from models.system_info import SystemInfoCollector


class MasterCollector:
    @staticmethod
    def collect_all(restart_failed_services_once: bool = True) -> dict:
        cycle_started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        logs = LogCollector.collect(since=cycle_started_at)
        service_diagnostics = ServiceDiagnostics.inspect_common_services(
            restart_once=restart_failed_services_once,
            since=cycle_started_at,
        )
        incident_classification = {}
        for service_name, details in service_diagnostics.items():
            if details.get("status") == "failed":
                incident_classification[service_name] = IncidentClassifier.classify_service_failure(
                    service_name,
                    details,
                    logs,
                )

        return {
            "system": SystemInfoCollector.collect(),
            "cycle_started_at": cycle_started_at,
            "cpu": CPUCollector.collect(),
            "memory": MemoryCollector.collect(),
            "disk": DiskCollector.collect(),
            "network": NetworkCollector.collect(),
            "processes": ProcessCollector.collect(),
            "services": ServiceCollector.collect(),
            "service_diagnostics": service_diagnostics,
            "incident_classification": incident_classification,
            "logs": logs,
            "container_logs": ContainerLogCollector.collect_all(),
        }

