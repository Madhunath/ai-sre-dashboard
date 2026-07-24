import os
import platform
import socket


class SystemInfoCollector:
    @staticmethod
    def collect() -> dict:
        return {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "python_version": platform.python_version(),
            "working_directory": os.getcwd(),
            "status": "success",
        }
