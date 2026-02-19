#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from db import Database, hash_password, migrate, seed_defaults

ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT / "frontend"
SECRET = os.getenv("APP_SECRET", "dev-share-transfer-secret")
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", str(60 * 60 * 8)))

DB = Database()


def now_dt() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now_dt().isoformat()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode())


def create_token(user_id: int, role: str, session_id: str) -> str:
    payload = {
        "uid": user_id,
        "role": role,
        "sid": session_id,
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    encoded = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(SECRET.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{sig}"


def decode_token(token: str):
    try:
        encoded, sig = token.split(".", 1)
        expected = hmac.new(SECRET.encode(), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(b64url_decode(encoded).decode())
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def generate_totp_secret() -> str:
    # 20 random bytes -> base32 w/o padding
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_code(secret_b32: str, at: int, digits: int = 6, step: int = 30) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    counter = int(at / step)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    val = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(val % (10**digits)).zfill(digits)


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    if not code or not code.isdigit() or len(code) != 6:
        return False
    now = int(time.time())
    for i in range(-window, window + 1):
        if hmac.compare_digest(_totp_code(secret_b32, now + i * 30), code):
            return True
    return False


def append_audit(conn, db: Database, event_type, actor_user_id, entity, entity_id, payload_dict):
    payload = json.dumps(payload_dict, separators=(",", ":"), sort_keys=True)
    prev = db.query_one(conn, "SELECT event_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    prev_hash = prev["event_hash"] if prev else ""
    material = f"{event_type}|{actor_user_id}|{entity}|{entity_id}|{payload}|{prev_hash}"
    event_hash = hashlib.sha256(material.encode()).hexdigest()
    db.execute(
        conn,
        """
        INSERT INTO audit_log(event_type, actor_user_id, entity, entity_id, payload, prev_hash, event_hash, created_at)
        VALUES (?,?,?,?,?,?,?,?)
        """,
        (event_type, actor_user_id, entity, entity_id, payload, prev_hash, event_hash, now_iso()),
    )


def require_role(user, accepted):
    return user and user.get("role") in accepted


def ensure_holding_row(conn, db: Database, user_id, symbol):
    row = db.query_one(conn, "SELECT quantity FROM holdings WHERE user_id=? AND symbol=?", (user_id, symbol))
    if row is None:
        db.execute(conn, "INSERT INTO holdings(user_id, symbol, quantity) VALUES (?,?,0)", (user_id, symbol))


def create_session(conn, db: Database, user_id: int, user_agent: str, ip: str) -> str:
    sid = secrets.token_urlsafe(24)
    expires_at = (now_dt() + timedelta(seconds=TOKEN_TTL_SECONDS)).isoformat()
    db.execute(
        conn,
        "INSERT INTO sessions(id, user_id, created_at, expires_at, user_agent, ip) VALUES (?,?,?,?,?,?)",
        (sid, user_id, now_iso(), expires_at, user_agent, ip),
    )
    return sid


def _is_session_active(conn, db: Database, sid: str):
    row = db.query_one(
        conn,
        "SELECT id, revoked_at, expires_at FROM sessions WHERE id=?",
        (sid,),
    )
    if not row:
        return False
    if row["revoked_at"]:
        return False
    expires = row["expires_at"]
    if isinstance(expires, datetime):
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now_dt():
            return False
    else:
        if str(expires) < now_iso():
            return False
    return True


def init_app():
    migrate(DB)
    seed_defaults(DB, now_iso, append_audit)


class Handler(BaseHTTPRequestHandler):
    server_version = "FinShareTransfer/2.0"

    def _json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _text_file(self, path: Path, content_type: str):
        if not path.exists() or not path.is_file():
            self.send_error(404)
            return
        content = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _parse_json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            return None

    def _get_auth_user(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        payload = decode_token(auth.split(" ", 1)[1])
        if not payload:
            return None

        conn = DB.connect()
        try:
            if not _is_session_active(conn, DB, payload.get("sid", "")):
                return None
            return payload
        finally:
            conn.close()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            return self._text_file(FRONTEND_DIR / "index.html", "text/html; charset=utf-8")
        if parsed.path == "/app.js":
            return self._text_file(FRONTEND_DIR / "app.js", "application/javascript; charset=utf-8")
        if parsed.path == "/styles.css":
            return self._text_file(FRONTEND_DIR / "styles.css", "text/css; charset=utf-8")
        if parsed.path == "/docs/openapi.yaml":
            return self._text_file(ROOT / "docs" / "openapi.yaml", "application/yaml; charset=utf-8")

        user = self._get_auth_user()

        if parsed.path == "/api/health":
            return self._json(200, {"ok": True, "timestamp": now_iso(), "engine": DB.engine})

        if parsed.path == "/api/me":
            if not user:
                return self._json(401, {"error": "Unauthorized"})
            conn = DB.connect()
            row = DB.query_one(
                conn,
                "SELECT id, email, role, twofa_enabled, created_at FROM users WHERE id=?",
                (user["uid"],),
            )
            conn.close()
            if not row:
                return self._json(401, {"error": "Unknown user"})
            return self._json(200, dict(row))

        if parsed.path == "/api/portfolios":
            if not user:
                return self._json(401, {"error": "Unauthorized"})
            conn = DB.connect()
            if user["role"] in ("ADMIN", "COMPLIANCE"):
                rows = DB.query_all(
                    conn,
                    """
                    SELECT u.id AS user_id, u.email, u.role, a.cash_balance,
                           COALESCE(h.symbol, '') AS symbol,
                           COALESCE(h.quantity, 0) AS quantity
                    FROM users u
                    JOIN accounts a ON a.user_id = u.id
                    LEFT JOIN holdings h ON h.user_id = u.id
                    ORDER BY u.id, h.symbol
                    """,
                )
            else:
                rows = DB.query_all(
                    conn,
                    """
                    SELECT u.id AS user_id, u.email, u.role, a.cash_balance,
                           COALESCE(h.symbol, '') AS symbol,
                           COALESCE(h.quantity, 0) AS quantity
                    FROM users u
                    JOIN accounts a ON a.user_id = u.id
                    LEFT JOIN holdings h ON h.user_id = u.id
                    WHERE u.id = ?
                    ORDER BY u.id, h.symbol
                    """,
                    (user["uid"],),
                )
            conn.close()
            grouped = {}
            for r in rows:
                uid = r["user_id"]
                if uid not in grouped:
                    grouped[uid] = {
                        "user_id": uid,
                        "email": r["email"],
                        "role": r["role"],
                        "cash_balance": r["cash_balance"],
                        "holdings": [],
                    }
                if r["symbol"]:
                    grouped[uid]["holdings"].append({"symbol": r["symbol"], "quantity": r["quantity"]})
            return self._json(200, {"portfolios": list(grouped.values())})

        if parsed.path == "/api/transfers":
            if not user:
                return self._json(401, {"error": "Unauthorized"})
            conn = DB.connect()
            if user["role"] in ("ADMIN", "COMPLIANCE"):
                rows = DB.query_all(
                    conn,
                    """
                    SELECT t.*, uf.email AS from_email, ut.email AS to_email, uc.email AS created_email,
                           ua.email AS approved_email, ur.email AS rejected_email, ue.email AS executed_email
                    FROM transfers t
                    JOIN users uf ON uf.id=t.from_user_id
                    JOIN users ut ON ut.id=t.to_user_id
                    JOIN users uc ON uc.id=t.created_by
                    LEFT JOIN users ua ON ua.id=t.approved_by
                    LEFT JOIN users ur ON ur.id=t.rejected_by
                    LEFT JOIN users ue ON ue.id=t.executed_by
                    ORDER BY t.id DESC
                    """,
                )
            else:
                rows = DB.query_all(
                    conn,
                    """
                    SELECT t.*, uf.email AS from_email, ut.email AS to_email, uc.email AS created_email,
                           ua.email AS approved_email, ur.email AS rejected_email, ue.email AS executed_email
                    FROM transfers t
                    JOIN users uf ON uf.id=t.from_user_id
                    JOIN users ut ON ut.id=t.to_user_id
                    JOIN users uc ON uc.id=t.created_by
                    LEFT JOIN users ua ON ua.id=t.approved_by
                    LEFT JOIN users ur ON ur.id=t.rejected_by
                    LEFT JOIN users ue ON ue.id=t.executed_by
                    WHERE t.from_user_id=? OR t.to_user_id=?
                    ORDER BY t.id DESC
                    """,
                    (user["uid"], user["uid"]),
                )
            conn.close()
            return self._json(200, {"transfers": [dict(r) for r in rows]})

        if parsed.path == "/api/audit":
            if not user or user["role"] not in ("ADMIN", "COMPLIANCE"):
                return self._json(403, {"error": "Access denied"})
            params = parse_qs(parsed.query)
            limit = min(int(params.get("limit", [50])[0]), 200)
            conn = DB.connect()
            rows = DB.query_all(
                conn,
                """
                SELECT a.*, u.email AS actor_email
                FROM audit_log a
                LEFT JOIN users u ON u.id = a.actor_user_id
                ORDER BY a.id DESC LIMIT ?
                """,
                (limit,),
            )
            conn.close()
            return self._json(200, {"audit": [dict(r) for r in rows]})

        if parsed.path == "/api/sessions":
            if not user:
                return self._json(401, {"error": "Unauthorized"})
            conn = DB.connect()
            rows = DB.query_all(
                conn,
                "SELECT id, user_agent, ip, created_at, expires_at, revoked_at FROM sessions WHERE user_id=? ORDER BY created_at DESC",
                (user["uid"],),
            )
            conn.close()
            return self._json(200, {"sessions": [dict(r) for r in rows], "current_session_id": user["sid"]})

        self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        payload = self._parse_json_body()
        if payload is None:
            return self._json(400, {"error": "Invalid JSON"})

        if parsed.path == "/api/register":
            email = str(payload.get("email", "")).strip().lower()
            password = str(payload.get("password", ""))
            role = str(payload.get("role", "TRADER")).upper()
            if role not in ("TRADER", "COMPLIANCE"):
                role = "TRADER"
            if not email or "@" not in email:
                return self._json(400, {"error": "Valid email is required"})
            if len(password) < 8:
                return self._json(400, {"error": "Password must be at least 8 characters"})

            conn = DB.connect()
            try:
                salt = secrets.token_bytes(16)
                pwd_hash = hash_password(password, salt)
                if DB.engine == "postgres":
                    uid = DB.query_one(
                        conn,
                        "INSERT INTO users(email, password_hash, salt, role, created_at) VALUES (?,?,?,?,?) RETURNING id",
                        (email, pwd_hash, salt.hex(), role, now_iso()),
                    )["id"]
                else:
                    DB.execute(
                        conn,
                        "INSERT INTO users(email, password_hash, salt, role, created_at) VALUES (?,?,?,?,?)",
                        (email, pwd_hash, salt.hex(), role, now_iso()),
                    )
                    uid = DB.get_last_insert_id(conn)
                DB.execute(conn, "INSERT INTO accounts(user_id, cash_balance) VALUES (?,?)", (uid, 100000.0))
                sid = create_session(conn, DB, uid, self.headers.get("User-Agent", ""), self.client_address[0])
                append_audit(conn, DB, "REGISTER", uid, "users", uid, {"email": email, "role": role})
                conn.commit()
            except Exception:
                conn.rollback()
                conn.close()
                return self._json(409, {"error": "Email already exists"})
            conn.close()
            token = create_token(uid, role, sid)
            return self._json(201, {"token": token})

        if parsed.path == "/api/login":
            email = str(payload.get("email", "")).strip().lower()
            password = str(payload.get("password", ""))
            otp = str(payload.get("otp", "")).strip()
            conn = DB.connect()
            row = DB.query_one(
                conn,
                "SELECT id, password_hash, salt, role, twofa_secret, twofa_enabled FROM users WHERE email=?",
                (email,),
            )
            if not row:
                conn.close()
                return self._json(401, {"error": "Invalid credentials"})

            candidate = hash_password(password, bytes.fromhex(row["salt"]))
            if not hmac.compare_digest(candidate, row["password_hash"]):
                conn.close()
                return self._json(401, {"error": "Invalid credentials"})

            if bool(row["twofa_enabled"]):
                if not otp:
                    conn.close()
                    return self._json(202, {"requires_2fa": True, "message": "OTP required"})
                if not verify_totp(row["twofa_secret"], otp):
                    conn.close()
                    return self._json(401, {"error": "Invalid OTP"})

            sid = create_session(conn, DB, row["id"], self.headers.get("User-Agent", ""), self.client_address[0])
            append_audit(conn, DB, "LOGIN", row["id"], "sessions", None, {"session_id": sid})
            conn.commit()
            conn.close()
            token = create_token(row["id"], row["role"], sid)
            return self._json(200, {"token": token})

        user = self._get_auth_user()
        if not user:
            return self._json(401, {"error": "Unauthorized"})

        if parsed.path == "/api/logout":
            conn = DB.connect()
            DB.execute(conn, "UPDATE sessions SET revoked_at=? WHERE id=?", (now_iso(), user["sid"]))
            append_audit(conn, DB, "LOGOUT", user["uid"], "sessions", None, {"session_id": user["sid"]})
            conn.commit()
            conn.close()
            return self._json(200, {"status": "logged_out"})

        if parsed.path == "/api/2fa/setup":
            conn = DB.connect()
            secret = generate_totp_secret()
            DB.execute(
                conn,
                "UPDATE users SET twofa_secret=?, twofa_enabled=0 WHERE id=?",
                (secret, user["uid"]),
            )
            append_audit(conn, DB, "TWOFA_SETUP", user["uid"], "users", user["uid"], {"enabled": False})
            conn.commit()
            conn.close()
            issuer = "FinShareTransfer"
            account = f"user-{user['uid']}"
            uri = f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
            return self._json(200, {"secret": secret, "otpauth_uri": uri})

        if parsed.path == "/api/2fa/enable":
            otp = str(payload.get("otp", "")).strip()
            conn = DB.connect()
            row = DB.query_one(conn, "SELECT twofa_secret FROM users WHERE id=?", (user["uid"],))
            if not row or not row["twofa_secret"]:
                conn.close()
                return self._json(400, {"error": "2FA secret not initialized. Call /api/2fa/setup first."})
            if not verify_totp(row["twofa_secret"], otp):
                conn.close()
                return self._json(401, {"error": "Invalid OTP"})
            DB.execute(conn, "UPDATE users SET twofa_enabled=1 WHERE id=?", (user["uid"],))
            append_audit(conn, DB, "TWOFA_ENABLED", user["uid"], "users", user["uid"], {"enabled": True})
            conn.commit()
            conn.close()
            return self._json(200, {"twofa_enabled": True})

        if parsed.path == "/api/2fa/disable":
            otp = str(payload.get("otp", "")).strip()
            conn = DB.connect()
            row = DB.query_one(conn, "SELECT twofa_secret, twofa_enabled FROM users WHERE id=?", (user["uid"],))
            if not row or not bool(row["twofa_enabled"]):
                conn.close()
                return self._json(400, {"error": "2FA is not enabled"})
            if not verify_totp(row["twofa_secret"], otp):
                conn.close()
                return self._json(401, {"error": "Invalid OTP"})
            DB.execute(conn, "UPDATE users SET twofa_enabled=0 WHERE id=?", (user["uid"],))
            append_audit(conn, DB, "TWOFA_DISABLED", user["uid"], "users", user["uid"], {"enabled": False})
            conn.commit()
            conn.close()
            return self._json(200, {"twofa_enabled": False})

        if parsed.path == "/api/sessions/revoke":
            sid = str(payload.get("session_id", "")).strip()
            if not sid:
                return self._json(400, {"error": "session_id is required"})
            conn = DB.connect()
            row = DB.query_one(conn, "SELECT user_id FROM sessions WHERE id=?", (sid,))
            if not row or int(row["user_id"]) != int(user["uid"]):
                conn.close()
                return self._json(404, {"error": "Session not found"})
            DB.execute(conn, "UPDATE sessions SET revoked_at=? WHERE id=?", (now_iso(), sid))
            append_audit(conn, DB, "SESSION_REVOKED", user["uid"], "sessions", None, {"session_id": sid})
            conn.commit()
            conn.close()
            return self._json(200, {"status": "revoked", "session_id": sid})

        if parsed.path == "/api/sessions/revoke-all":
            keep_current = bool(payload.get("keep_current", False))
            conn = DB.connect()
            if keep_current:
                DB.execute(
                    conn,
                    "UPDATE sessions SET revoked_at=? WHERE user_id=? AND id<>? AND revoked_at IS NULL",
                    (now_iso(), user["uid"], user["sid"]),
                )
            else:
                DB.execute(
                    conn,
                    "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
                    (now_iso(), user["uid"]),
                )
            append_audit(conn, DB, "SESSIONS_REVOKED_ALL", user["uid"], "sessions", None, {"keep_current": keep_current})
            conn.commit()
            conn.close()
            return self._json(200, {"status": "revoked_all", "keep_current": keep_current})

        if parsed.path == "/api/transfers":
            if user["role"] not in ("TRADER", "ADMIN"):
                return self._json(403, {"error": "Only traders or admins can create transfers"})
            to_email = str(payload.get("to_email", "")).strip().lower()
            symbol = str(payload.get("symbol", "")).strip().upper()
            quantity = int(payload.get("quantity", 0))
            price_per_share = float(payload.get("price_per_share", 0))

            if not to_email or not symbol or quantity <= 0 or price_per_share <= 0:
                return self._json(400, {"error": "to_email, symbol, quantity, and price_per_share are required"})

            conn = DB.connect()
            to_user = DB.query_one(conn, "SELECT id FROM users WHERE email=?", (to_email,))
            if not to_user:
                conn.close()
                return self._json(404, {"error": "Recipient not found"})
            if to_user["id"] == user["uid"]:
                conn.close()
                return self._json(400, {"error": "Self-transfer is not allowed"})

            from_holding = DB.query_one(
                conn,
                "SELECT quantity FROM holdings WHERE user_id=? AND symbol=?",
                (user["uid"], symbol),
            )
            available = from_holding["quantity"] if from_holding else 0
            if int(available) < quantity:
                conn.close()
                return self._json(422, {"error": f"Insufficient holdings. Available: {available}"})

            total = round(quantity * price_per_share, 2)
            if DB.engine == "postgres":
                transfer_id = DB.query_one(
                    conn,
                    """
                    INSERT INTO transfers(
                        from_user_id, to_user_id, symbol, quantity, price_per_share,
                        total_amount, status, created_by, created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?) RETURNING id
                    """,
                    (user["uid"], to_user["id"], symbol, quantity, price_per_share, total, "PENDING", user["uid"], now_iso()),
                )["id"]
            else:
                DB.execute(
                    conn,
                    """
                    INSERT INTO transfers(
                        from_user_id, to_user_id, symbol, quantity, price_per_share,
                        total_amount, status, created_by, created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (user["uid"], to_user["id"], symbol, quantity, price_per_share, total, "PENDING", user["uid"], now_iso()),
                )
                transfer_id = DB.get_last_insert_id(conn)

            append_audit(
                conn,
                DB,
                "TRANSFER_CREATED",
                user["uid"],
                "transfers",
                transfer_id,
                {
                    "from_user_id": user["uid"],
                    "to_user_id": to_user["id"],
                    "symbol": symbol,
                    "quantity": quantity,
                    "price_per_share": price_per_share,
                    "total_amount": total,
                },
            )
            conn.commit()
            conn.close()
            return self._json(201, {"transfer_id": transfer_id, "status": "PENDING"})

        parts = parsed.path.strip("/").split("/")
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "transfers":
            try:
                transfer_id = int(parts[2])
            except ValueError:
                return self._json(400, {"error": "Invalid transfer id"})
            action = parts[3]

            conn = DB.connect()
            transfer = DB.query_one(conn, "SELECT * FROM transfers WHERE id=?", (transfer_id,))
            if not transfer:
                conn.close()
                return self._json(404, {"error": "Transfer not found"})

            if action == "approve":
                if not require_role(user, {"COMPLIANCE", "ADMIN"}):
                    conn.close()
                    return self._json(403, {"error": "Only compliance/admin can approve"})
                if transfer["status"] != "PENDING":
                    conn.close()
                    return self._json(409, {"error": "Only pending transfers can be approved"})
                DB.execute(
                    conn,
                    "UPDATE transfers SET status='APPROVED', approved_by=?, approved_at=? WHERE id=?",
                    (user["uid"], now_iso(), transfer_id),
                )
                append_audit(conn, DB, "TRANSFER_APPROVED", user["uid"], "transfers", transfer_id, {"status": "APPROVED"})
                conn.commit()
                conn.close()
                return self._json(200, {"status": "APPROVED"})

            if action == "reject":
                if not require_role(user, {"COMPLIANCE", "ADMIN"}):
                    conn.close()
                    return self._json(403, {"error": "Only compliance/admin can reject"})
                if transfer["status"] != "PENDING":
                    conn.close()
                    return self._json(409, {"error": "Only pending transfers can be rejected"})
                reason = str(payload.get("reason", "Policy review failed")).strip() or "Policy review failed"
                DB.execute(
                    conn,
                    "UPDATE transfers SET status='REJECTED', rejected_by=?, rejected_at=?, reason=? WHERE id=?",
                    (user["uid"], now_iso(), reason, transfer_id),
                )
                append_audit(conn, DB, "TRANSFER_REJECTED", user["uid"], "transfers", transfer_id, {"status": "REJECTED", "reason": reason})
                conn.commit()
                conn.close()
                return self._json(200, {"status": "REJECTED"})

            if action == "execute":
                if not require_role(user, {"COMPLIANCE", "ADMIN"}):
                    conn.close()
                    return self._json(403, {"error": "Only compliance/admin can execute"})
                if transfer["status"] != "APPROVED":
                    conn.close()
                    return self._json(409, {"error": "Only approved transfers can be executed"})

                try:
                    from_h = DB.query_one(
                        conn,
                        "SELECT quantity FROM holdings WHERE user_id=? AND symbol=?",
                        (transfer["from_user_id"], transfer["symbol"]),
                    )
                    from_qty = from_h["quantity"] if from_h else 0
                    if int(from_qty) < int(transfer["quantity"]):
                        raise ValueError("Source holdings became insufficient")

                    to_acct = DB.query_one(
                        conn,
                        "SELECT cash_balance FROM accounts WHERE user_id=?",
                        (transfer["to_user_id"],),
                    )
                    if not to_acct or float(to_acct["cash_balance"]) < float(transfer["total_amount"]):
                        raise ValueError("Recipient has insufficient cash balance")

                    ensure_holding_row(conn, DB, transfer["to_user_id"], transfer["symbol"])

                    DB.execute(
                        conn,
                        "UPDATE holdings SET quantity = quantity - ? WHERE user_id=? AND symbol=?",
                        (transfer["quantity"], transfer["from_user_id"], transfer["symbol"]),
                    )
                    DB.execute(
                        conn,
                        "UPDATE holdings SET quantity = quantity + ? WHERE user_id=? AND symbol=?",
                        (transfer["quantity"], transfer["to_user_id"], transfer["symbol"]),
                    )
                    DB.execute(
                        conn,
                        "UPDATE accounts SET cash_balance = cash_balance - ? WHERE user_id=?",
                        (transfer["total_amount"], transfer["to_user_id"]),
                    )
                    DB.execute(
                        conn,
                        "UPDATE accounts SET cash_balance = cash_balance + ? WHERE user_id=?",
                        (transfer["total_amount"], transfer["from_user_id"]),
                    )
                    DB.execute(
                        conn,
                        "UPDATE transfers SET status='EXECUTED', executed_by=?, executed_at=? WHERE id=?",
                        (user["uid"], now_iso(), transfer_id),
                    )
                    append_audit(
                        conn,
                        DB,
                        "TRANSFER_EXECUTED",
                        user["uid"],
                        "transfers",
                        transfer_id,
                        {
                            "status": "EXECUTED",
                            "cash_amount": transfer["total_amount"],
                            "symbol": transfer["symbol"],
                            "quantity": transfer["quantity"],
                        },
                    )
                    conn.commit()
                except ValueError as exc:
                    conn.rollback()
                    conn.close()
                    return self._json(422, {"error": str(exc)})

                conn.close()
                return self._json(200, {"status": "EXECUTED"})

            conn.close()
            return self._json(404, {"error": "Unsupported transfer action"})

        return self._json(404, {"error": "Route not found"})


def create_server(host: str, port: int):
    init_app()
    return HTTPServer((host, port), Handler)


def run():
    host = "0.0.0.0"
    port = int(os.getenv("PORT", "8080"))
    server = create_server(host, port)
    print(f"FinShareTransfer running at http://{host}:{port} (db={DB.engine})")
    server.serve_forever()


if __name__ == "__main__":
    run()
