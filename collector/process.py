import psutil
import time

class ProcessCollector:
    @staticmethod
    def collect(limit: int = 10) -> dict:
        try:
            processes = []
            
            # First pass: Initialize the CPU counters for all running processes
            for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'create_time']):
                try:
                    # Calling cpu_percent(interval=None) primes the internal counter
                    proc.cpu_percent(interval=None)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Give the OS a brief window (0.2 seconds) to accumulate CPU ticks
            time.sleep(0.2)

            # Second pass: Measure the actual delta
            for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'create_time']):
                try:
                    # Now this returns the true utilization over that 0.2s window
                    cpu_pct = proc.cpu_percent(interval=None)
                    mem_info = proc.memory_percent()
                    
                    # Fetch basic info block
                    info = proc.info
                    info['cpu_percent'] = cpu_pct
                    info['memory_percent'] = mem_info
                    processes.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort dynamically by the newly calculated CPU delta
            top_cpu = sorted(processes, key=lambda x: x.get('cpu_percent') or 0, reverse=True)[:limit]
            top_mem = sorted(processes, key=lambda x: x.get('memory_percent') or 0, reverse=True)[:limit]
            
            return {
                "top_cpu_consumers": top_cpu,
                "top_memory_consumers": top_mem,
                "total_running_processes": len(processes),
                "status": "success"
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
