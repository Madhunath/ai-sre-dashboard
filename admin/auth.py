import json

import pymysql
from werkzeug.security import check_password_hash, generate_password_hash

from config import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    MYSQL_DATABASE,
    MYSQL_HOST,
    MYSQL_PASSWORD,
    MYSQL_PORT,
    MYSQL_USER,
)


def get_connection(database: str | None = MYSQL_DATABASE):
    return pymysql.connect(
        host=MYSQL_HOST, port=MYSQL_PORT, user=MYSQL_USER, password=MYSQL_PASSWORD,
        database=database, cursorclass=pymysql.cursors.DictCursor, autocommit=True,
    )


def _ensure_column(cursor, name: str, definition: str) -> None:
    cursor.execute("SHOW COLUMNS FROM admin_users LIKE %s", (name,))
    if not cursor.fetchone():
        cursor.execute(f"ALTER TABLE admin_users ADD COLUMN {definition}")


def init_admin_db() -> None:
    with get_connection(database=None) as connection:
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DATABASE}`")

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS admin_users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(80) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) NOT NULL DEFAULT 'admin',
                    allowed_log_sources TEXT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Migrate installations created before viewer accounts existed.
            _ensure_column(cursor, "role", "role VARCHAR(20) NOT NULL DEFAULT 'admin'")
            _ensure_column(cursor, "allowed_log_sources", "allowed_log_sources TEXT NULL")
            _ensure_column(cursor, "is_active", "is_active BOOLEAN NOT NULL DEFAULT TRUE")

            # Create remediation audit table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS remediation_audit (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    operator VARCHAR(80) NOT NULL,
                    command VARCHAR(255) NOT NULL,
                    exit_code INT NOT NULL,
                    stdout TEXT NULL,
                    stderr TEXT NULL,
                    success BOOLEAN NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)


def _sources_to_json(sources: list[str]) -> str:
    return json.dumps(sorted({source.strip() for source in sources if source.strip()}))


def _sources_from_value(value: str | None) -> list[str]:
    try:
        return [str(source) for source in json.loads(value or "[]")]
    except (TypeError, ValueError):
        return []


def create_admin_user(username: str, password: str) -> None:
    init_admin_db()
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO admin_users (username, password_hash, role, allowed_log_sources, is_active)
                VALUES (%s, %s, 'admin', %s, TRUE)
                ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), role = 'admin', is_active = TRUE
            """, (username, generate_password_hash(password), _sources_to_json(["*"])))


def seed_admin_user() -> bool:
    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        raise RuntimeError("ADMIN_USERNAME and ADMIN_PASSWORD must be configured before starting the receiver.")
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM admin_users WHERE username = %s", (ADMIN_USERNAME,))
            if cursor.fetchone():
                cursor.execute("UPDATE admin_users SET role = 'admin', is_active = TRUE WHERE username = %s", (ADMIN_USERNAME,))
                return False
            cursor.execute("""
                INSERT INTO admin_users (username, password_hash, role, allowed_log_sources, is_active)
                VALUES (%s, %s, 'admin', %s, TRUE)
            """, (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), _sources_to_json(["*"])))
    return True


def bootstrap_admin_db() -> bool:
    init_admin_db()
    return seed_admin_user()


def authenticate_user(username: str, password: str) -> dict | None:
    init_admin_db()
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT username, password_hash, role, allowed_log_sources, is_active
                FROM admin_users WHERE username = %s
            """, (username,))
            row = cursor.fetchone()
    if not row or not row["is_active"] or not check_password_hash(row["password_hash"], password):
        return None
    return {"username": row["username"], "role": row["role"], "allowed_sources": _sources_from_value(row["allowed_log_sources"])}


def create_viewer(username: str, password: str, allowed_sources: list[str]) -> None:
    if not username or not password:
        raise ValueError("Username and password are required.")
    init_admin_db()
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO admin_users (username, password_hash, role, allowed_log_sources, is_active)
                VALUES (%s, %s, 'viewer', %s, TRUE)
            """, (username, generate_password_hash(password), _sources_to_json(allowed_sources)))


def list_viewers() -> list[dict]:
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT username, allowed_log_sources, is_active, created_at
                FROM admin_users WHERE role = 'viewer' ORDER BY username
            """)
            rows = cursor.fetchall()
    for row in rows:
        row["allowed_sources"] = _sources_from_value(row.pop("allowed_log_sources"))
    return rows


def get_user_allowed_sources(username: str) -> list[str]:
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT allowed_log_sources FROM admin_users WHERE username = %s", (username,))
            row = cursor.fetchone()
            if row:
                return _sources_from_value(row["allowed_log_sources"])
    return []


def update_viewer(username: str, allowed_sources: list[str], is_active: bool, password: str = "") -> None:
    with get_connection() as connection:
        with connection.cursor() as cursor:
            if password:
                cursor.execute("""
                    UPDATE admin_users SET allowed_log_sources = %s, is_active = %s, password_hash = %s
                    WHERE username = %s AND role = 'viewer'
                """, (_sources_to_json(allowed_sources), is_active, generate_password_hash(password), username))
            else:
                cursor.execute("""
                    UPDATE admin_users SET allowed_log_sources = %s, is_active = %s
                    WHERE username = %s AND role = 'viewer'
                """, (_sources_to_json(allowed_sources), is_active, username))


def authenticate_admin(username: str, password: str) -> bool:
    user = authenticate_user(username, password)
    return bool(user and user["role"] == "admin")


def delete_viewer(username: str) -> None:
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM admin_users WHERE username = %s AND role = 'viewer'", (username,))


def log_remediation_audit(operator: str, command: str, exit_code: int, stdout: str, stderr: str, success: bool) -> None:
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO remediation_audit (operator, command, exit_code, stdout, stderr, success)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (operator, command, exit_code, stdout, stderr, success))


def list_remediation_audits() -> list[dict]:
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT operator, command, exit_code, stdout, stderr, success, created_at
                FROM remediation_audit ORDER BY created_at DESC LIMIT 100
            """)
            rows = cursor.fetchall()
            for r in rows:
                r["created_at"] = r["created_at"].isoformat()
            return rows
