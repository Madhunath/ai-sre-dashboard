import os
import tempfile


def _load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return

    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            name, value = line.split("=", 1)
            name = name.strip()
            value = value.strip().strip('"').strip("'")
            if name and name not in os.environ:
                os.environ[name] = value


_load_dotenv()


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip() or default

DEFAULT_MONITOR_INTERVAL_SECONDS = int(_env("MONITOR_INTERVAL_SECONDS", _env("LOCAL_MONITOR_INTERVAL_SECONDS", "15")))
DEFAULT_LOG_LINES = int(_env("DEFAULT_LOG_LINES", "80"))
DEFAULT_HEALTHCHECK_URLS = [
    url.strip()
    for url in _env("HEALTHCHECK_URLS").split(",")
    if url.strip()
]

MONITORING_MODE = _env("MONITORING_MODE", "continuous")

GEMINI_API_KEY = _env("GEMINI_API_KEY")

AWS_REGION = _env("AWS_REGION", "us-west-1")
SNS_TOPIC_ARN = _env("SNS_TOPIC_ARN")

SRE_COOLDOWN_LOCK_FILE = _env(
    "SRE_COOLDOWN_LOCK_FILE",
    os.path.join(tempfile.gettempdir(), "sre_agent_cooldown.lock"),
)
SRE_STATE_FILE = _env(
    "SRE_STATE_FILE",
    os.path.join(tempfile.gettempdir(), "sre_agent_state.json"),
)
SRE_COOLDOWN_PERIOD_SECONDS = int(_env("SRE_COOLDOWN_PERIOD_SECONDS", "30"))
AUTO_RESTART_FAILED_SERVICE_ONCE = _env("AUTO_RESTART_FAILED_SERVICE_ONCE", "true").lower() == "true"
AUTO_KILL_PROCESS = _env("AUTO_KILL_PROCESS", "false").lower() == "true"

ADMIN_SECRET_KEY = _env("ADMIN_SECRET_KEY", "change-this-admin-secret")
ADMIN_USERNAME = _env("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = _env("ADMIN_PASSWORD")
MYSQL_HOST = _env("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(_env("MYSQL_PORT", "3306"))
MYSQL_USER = _env("MYSQL_USER", "sre_admin")
MYSQL_PASSWORD = _env("MYSQL_PASSWORD")
MYSQL_DATABASE = _env("MYSQL_DATABASE", "sre_agent")


def validate_config() -> None:
    """Validate that monitoring, cooldown, and logging intervals are sound and logical."""
    if DEFAULT_MONITOR_INTERVAL_SECONDS <= 0:
        raise ValueError(f"MONITOR_INTERVAL_SECONDS must be a positive integer, got {DEFAULT_MONITOR_INTERVAL_SECONDS}")

    if SRE_COOLDOWN_PERIOD_SECONDS <= 0:
        raise ValueError(f"SRE_COOLDOWN_PERIOD_SECONDS must be a positive integer, got {SRE_COOLDOWN_PERIOD_SECONDS}")

    if DEFAULT_LOG_LINES <= 0 or DEFAULT_LOG_LINES > 1000:
        raise ValueError(f"DEFAULT_LOG_LINES must be a positive integer between 1 and 1000, got {DEFAULT_LOG_LINES}")

    if SRE_COOLDOWN_PERIOD_SECONDS < DEFAULT_MONITOR_INTERVAL_SECONDS:
        raise ValueError(
            f"SRE_COOLDOWN_PERIOD_SECONDS ({SRE_COOLDOWN_PERIOD_SECONDS}) cannot be less than "
            f"MONITOR_INTERVAL_SECONDS ({DEFAULT_MONITOR_INTERVAL_SECONDS}). Cooldown must be at least as long as the monitoring interval."
        )


validate_config()

