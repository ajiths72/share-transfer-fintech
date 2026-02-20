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


def _sqlite_column_exists(conn, table: str, column: str) -> bool:  # noqa: ANN001
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)


def _sqlite_table_exists(conn, table: str) -> bool:  # noqa: ANN001
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _postgres_column_exists(db: Database, conn, table: str, column: str) -> bool:  # noqa: ANN001
    row = db.query_one(
        conn,
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name=? AND column_name=?
        """,
        (table, column),
    )
    return row is not None


def _postgres_table_exists(db: Database, conn, table: str) -> bool:  # noqa: ANN001
    row = db.query_one(
        conn,
        """
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema='public' AND table_name=?
        """,
        (table,),
    )
    return row is not None


def _ensure_backfill_schema(db: Database, conn):  # noqa: ANN001
    # Backfill legacy DBs that predate security/session additions.
    if db.engine == "sqlite":
        if _sqlite_table_exists(conn, "users"):
            if not _sqlite_column_exists(conn, "users", "twofa_secret"):
                conn.execute("ALTER TABLE users ADD COLUMN twofa_secret TEXT")
            if not _sqlite_column_exists(conn, "users", "twofa_enabled"):
                conn.execute("ALTER TABLE users ADD COLUMN twofa_enabled INTEGER NOT NULL DEFAULT 0")

        if not _sqlite_table_exists(conn, "sessions"):
            conn.executescript(
                """
                CREATE TABLE sessions (
                  id TEXT PRIMARY KEY,
                  user_id INTEGER NOT NULL,
                  created_at TEXT NOT NULL,
                  expires_at TEXT NOT NULL,
                  revoked_at TEXT,
                  user_agent TEXT,
                  ip TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(id)
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
                """
            )
        if not _sqlite_table_exists(conn, "market_symbols"):
            conn.executescript(
                """
                CREATE TABLE market_symbols (
                  symbol TEXT PRIMARY KEY,
                  name TEXT NOT NULL,
                  last_price REAL NOT NULL,
                  is_active INTEGER NOT NULL DEFAULT 1,
                  updated_at TEXT NOT NULL
                );
                """
            )
        if not _sqlite_table_exists(conn, "market_orders"):
            conn.executescript(
                """
                CREATE TABLE market_orders (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  symbol TEXT NOT NULL,
                  quantity INTEGER NOT NULL,
                  price_per_share REAL NOT NULL,
                  total_amount REAL NOT NULL,
                  status TEXT NOT NULL CHECK(status IN ('EXECUTED')),
                  created_at TEXT NOT NULL,
                  FOREIGN KEY(user_id) REFERENCES users(id),
                  FOREIGN KEY(symbol) REFERENCES market_symbols(symbol)
                );
                CREATE INDEX IF NOT EXISTS idx_market_orders_user_id ON market_orders(user_id);
                CREATE INDEX IF NOT EXISTS idx_market_orders_symbol ON market_orders(symbol);
                """
            )
        if not _sqlite_table_exists(conn, "limit_orders"):
            conn.executescript(
                """
                CREATE TABLE limit_orders (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  symbol TEXT NOT NULL,
                  quantity INTEGER NOT NULL,
                  limit_price REAL NOT NULL,
                  status TEXT NOT NULL CHECK(status IN ('PENDING','EXECUTED','CANCELED')),
                  created_at TEXT NOT NULL,
                  canceled_at TEXT,
                  executed_at TEXT,
                  executed_price REAL,
                  total_amount REAL,
                  FOREIGN KEY(user_id) REFERENCES users(id),
                  FOREIGN KEY(symbol) REFERENCES market_symbols(symbol)
                );
                CREATE INDEX IF NOT EXISTS idx_limit_orders_user_id ON limit_orders(user_id);
                CREATE INDEX IF NOT EXISTS idx_limit_orders_status ON limit_orders(status);
                """
            )
        return

    if _postgres_table_exists(db, conn, "users"):
        if not _postgres_column_exists(db, conn, "users", "twofa_secret"):
            db.execute(conn, "ALTER TABLE users ADD COLUMN twofa_secret TEXT")
        if not _postgres_column_exists(db, conn, "users", "twofa_enabled"):
            db.execute(conn, "ALTER TABLE users ADD COLUMN twofa_enabled BOOLEAN NOT NULL DEFAULT FALSE")

    if not _postgres_table_exists(db, conn, "sessions"):
        db.run_script(
            conn,
            """
            CREATE TABLE sessions (
              id TEXT PRIMARY KEY,
              user_id BIGINT NOT NULL REFERENCES users(id),
              created_at TIMESTAMPTZ NOT NULL,
              expires_at TIMESTAMPTZ NOT NULL,
              revoked_at TIMESTAMPTZ,
              user_agent TEXT,
              ip TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
            """,
        )
    if not _postgres_table_exists(db, conn, "market_symbols"):
        db.run_script(
            conn,
            """
            CREATE TABLE market_symbols (
              symbol TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              last_price DOUBLE PRECISION NOT NULL,
              is_active BOOLEAN NOT NULL DEFAULT TRUE,
              updated_at TIMESTAMPTZ NOT NULL
            );
            """,
        )
    if not _postgres_table_exists(db, conn, "market_orders"):
        db.run_script(
            conn,
            """
            CREATE TABLE market_orders (
              id BIGSERIAL PRIMARY KEY,
              user_id BIGINT NOT NULL REFERENCES users(id),
              symbol TEXT NOT NULL REFERENCES market_symbols(symbol),
              quantity BIGINT NOT NULL,
              price_per_share DOUBLE PRECISION NOT NULL,
              total_amount DOUBLE PRECISION NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('EXECUTED')),
              created_at TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_market_orders_user_id ON market_orders(user_id);
            CREATE INDEX IF NOT EXISTS idx_market_orders_symbol ON market_orders(symbol);
            """,
        )
    if not _postgres_table_exists(db, conn, "limit_orders"):
        db.run_script(
            conn,
            """
            CREATE TABLE limit_orders (
              id BIGSERIAL PRIMARY KEY,
              user_id BIGINT NOT NULL REFERENCES users(id),
              symbol TEXT NOT NULL REFERENCES market_symbols(symbol),
              quantity BIGINT NOT NULL,
              limit_price DOUBLE PRECISION NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('PENDING','EXECUTED','CANCELED')),
              created_at TIMESTAMPTZ NOT NULL,
              canceled_at TIMESTAMPTZ,
              executed_at TIMESTAMPTZ,
              executed_price DOUBLE PRECISION,
              total_amount DOUBLE PRECISION
            );
            CREATE INDEX IF NOT EXISTS idx_limit_orders_user_id ON limit_orders(user_id);
            CREATE INDEX IF NOT EXISTS idx_limit_orders_status ON limit_orders(status);
            """,
        )


def migrate(db: Database):
    conn = db.connect()
    try:
        root = Path(__file__).resolve().parent / "migrations"
        folder = root / ("postgres" if db.engine == "postgres" else "sqlite")
        _apply_migrations_for_engine(db, conn, folder)
        _ensure_backfill_schema(db, conn)
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
