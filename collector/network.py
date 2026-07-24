import shutil
import socket
import subprocess


class NetworkCollector:
    @staticmethod
    def collect() -> dict:
        data = {
            "interfaces": [],
            "open_ports": [],
            "status": "success",
        }

        try:
            import psutil

            for interface, addrs in psutil.net_if_addrs().items():
                addresses = [addr.address for addr in addrs if getattr(addr, "address", None)]
                if addresses:
                    data["interfaces"].append({"name": interface, "addresses": addresses})
        except Exception as exc:
            data["interfaces"] = []
            data["network_error"] = str(exc)

        try:
            for port in [22, 80, 443, 3306, 5432]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()
                data["open_ports"].append({"port": port, "open": result == 0})
        except Exception as exc:
            data["network_error"] = str(exc)

        try:
            traceroute = shutil.which("traceroute")
            if traceroute:
                subprocess.run([traceroute, "-m", "3", "8.8.8.8"], capture_output=True, text=True, timeout=5)
        except Exception:
            pass

        return data
