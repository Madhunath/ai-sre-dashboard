import psutil
import os

class CPUCollector:
    @staticmethod
    def collect() -> dict:
        try:
            load_avg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
            return {
                "utilization_pct": psutil.cpu_percent(interval=0.5),
                "per_cpu_pct": psutil.cpu_percent(interval=0.1, percpu=True),
                "physical_cores": psutil.cpu_count(logical=False),
                "logical_cores": psutil.cpu_count(logical=True),
                "load_average": {
                    "1m": load_avg[0],
                    "5m": load_avg[1],
                    "15m": load_avg[2]
                },
                "stats": psutil.cpu_stats()._asdict(),
                "status": "success"
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
