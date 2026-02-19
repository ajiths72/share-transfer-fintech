import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SQLITE_PATH = ROOT / "backend" / "fintech.db"


class Database:
    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_SQLITE_PATH}")
        self.engine = "postgres" if self.database_url.startswith("postgresql://") else "sqlite"

    def connect(self):
        if self.engine == "sqlite":
            path = self.database_url.replace("sqlite:///", "", 1)
            conn = sqlite3.connect(path)
            conn.row_factory = sqlite3.Row
            return conn

        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("psycopg is required for PostgreSQL. Install dependencies first.") from exc
        conn = psycopg.connect(self.database_url, row_factory=dict_row)
        return conn

    def _adapt_sql(self, sql: str) -> str:
        if self.engine == "postgres":
            return sql.replace("?", "%s")
        return sql

    def execute(self, conn, sql: str, params: Iterable[Any] = ()):  # noqa: ANN001
        cur = conn.cursor()
        cur.execute(self._adapt_sql(sql), tuple(params))
        return cur

    def query_all(self, conn, sql: str, params: Iterable[Any] = ()):  # noqa: ANN001
        return self.execute(conn, sql, params).fetchall()

    def query_one(self, conn, sql: str, params: Iterable[Any] = ()):  # noqa: ANN001
        return self.execute(conn, sql, params).fetchone()

    def run_script(self, conn, sql: str):  # noqa: ANN001
        if self.engine == "sqlite":
            conn.executescript(sql)
            return
        cur = conn.cursor()
        cur.execute(sql)

    def get_last_insert_id(self, conn):  # noqa: ANN001
        if self.engine == "sqlite":
            row = self.query_one(conn, "SELECT last_insert_rowid() AS id")
            return int(row["id"]) if row else None
        # For postgres, prefer INSERT ... RETURNING in caller
        return None


def _apply_migrations_for_engine(db: Database, conn, migrations_dir: Path):  # noqa: ANN001
    db.execute(
        conn,
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """,
    )

    applied = {
        row["version"]
        for row in db.query_all(conn, "SELECT version FROM schema_migrations")
    }

    for file in sorted(migrations_dir.glob("*.sql")):
        version = file.name
        if version in applied:
            continue
        db.run_script(conn, file.read_text())
        applied_at_expr = "datetime('now')" if db.engine == "sqlite" else "CURRENT_TIMESTAMP"
        db.execute(
            conn,
            f"INSERT INTO schema_migrations(version, applied_at) VALUES(?, {applied_at_expr})",
            (version,),
        )


def migrate(db: Database):
    conn = db.connect()
    try:
        root = Path(__file__).resolve().parent / "migrations"
        folder = root / ("postgres" if db.engine == "postgres" else "sqlite")
        _apply_migrations_for_engine(db, conn, folder)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def hash_password(password: str, salt: bytes) -> str:
    import hashlib

    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000).hex()


def seed_defaults(db: Database, now_iso, append_audit):
    conn = db.connect()
    try:
        defaults = [
            ("alice@fintrade.com", "alice123", "TRADER", 250000.0, [("ACME", 1000), ("TSLA", 120)]),
            ("bob@fintrade.com", "bob123", "TRADER", 180000.0, [("ACME", 250), ("MSFT", 300)]),
            ("compliance@fintrade.com", "comply123", "COMPLIANCE", 0.0, []),
            ("admin@fintrade.com", "admin123", "ADMIN", 500000.0, [("AAPL", 500)]),
        ]

        for email, password, role, cash, holdings in defaults:
            row = db.query_one(conn, "SELECT id FROM users WHERE email=?", (email,))
            if row:
                continue
            salt = secrets.token_bytes(16)
            pwd_hash = hash_password(password, salt)
            created_at = now_iso()

            if db.engine == "postgres":
                uid = db.query_one(
                    conn,
                    "INSERT INTO users(email, password_hash, salt, role, created_at) VALUES (?,?,?,?,?) RETURNING id",
                    (email, pwd_hash, salt.hex(), role, created_at),
                )["id"]
            else:
                db.execute(
                    conn,
                    "INSERT INTO users(email, password_hash, salt, role, created_at) VALUES (?,?,?,?,?)",
                    (email, pwd_hash, salt.hex(), role, created_at),
                )
                uid = db.get_last_insert_id(conn)

            db.execute(conn, "INSERT INTO accounts(user_id, cash_balance) VALUES (?,?)", (uid, cash))
            for symbol, qty in holdings:
                db.execute(
                    conn,
                    "INSERT INTO holdings(user_id, symbol, quantity) VALUES (?,?,?)",
                    (uid, symbol, qty),
                )
            append_audit(conn, db, "REGISTER", uid, "users", uid, {"email": email, "role": role})
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
