import psutil
import subprocess

class DiskCollector:
    @staticmethod
    def collect() -> dict:
        try:
            partitions = []
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    partitions.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "total_bytes": usage.total,
                        "used_bytes": usage.used,
                        "free_bytes": usage.free,
                        "pct_used": usage.percent
                    })
                    if usage.percent >= 80:
                        result = subprocess.run(
                            ["du", "-x", "-h", "--max-depth=1", part.mountpoint],
                            capture_output=True, text=True, timeout=20,
                        )
                        largest = sorted(
                            result.stdout.splitlines(),
                            key=lambda line: _size_bytes(line.split("\t", 1)[0]) if "\t" in line else 0,
                            reverse=True,
                        )[:12]
                        partitions[-1]["largest_directories"] = largest
                except PermissionError:
                    continue
            
            io_counters = psutil.disk_io_counters()
            return {
                "partitions": partitions,
                "io_counters": io_counters._asdict() if io_counters else {},
                "status": "success"
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}


def _size_bytes(value: str) -> int:
    units = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    try:
        suffix = value[-1].upper()
        return int(float(value[:-1]) * units.get(suffix, 1)) if suffix in units else int(value)
    except ValueError:
        return 0
