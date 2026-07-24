import psutil

class MemoryCollector:
    @staticmethod
    def collect() -> dict:
        try:
            vm = psutil.virtual_memory()
            swap = psutil.swap_memory()
            return {
                "virtual": {
                    "total_bytes": vm.total,
                    "available_bytes": vm.available,
                    "used_bytes": vm.used,
                    "pct_used": vm.percent,
                    "cached_bytes": getattr(vm, "cached", 0),
                    "buffers_bytes": getattr(vm, "buffers", 0)
                },
                "swap": {
                    "total_bytes": swap.total,
                    "used_bytes": swap.used,
                    "free_bytes": swap.free,
                    "pct_used": swap.percent
                },
                "status": "success"
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
