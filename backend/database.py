import os
from contextlib import contextmanager
import psycopg2
from psycopg2.extras import RealDictCursor

DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "database": os.getenv("DB_NAME", "phishguard"),
    "user":     os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", "password"),
    "port":     int(os.getenv("DB_PORT", "5432")),
}


@contextmanager
def get_conn():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                email         VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at    TIMESTAMP DEFAULT NOW()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id             SERIAL PRIMARY KEY,
                user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
                message_text   TEXT NOT NULL,
                risk_score     INTEGER NOT NULL,
                classification VARCHAR(20) NOT NULL,
                patterns       TEXT[],
                recommendation TEXT,
                channel        VARCHAR(10) DEFAULT 'web',
                analyzed_at    TIMESTAMP DEFAULT NOW()
            );
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_user
            ON messages(user_id, analyzed_at DESC);
        """)


# ── Users ──────────────────────────────────────────────────────────
def create_user(email: str, password_hash: str) -> dict:
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id, email, created_at",
            (email, password_hash),
        )
        return dict(cur.fetchone())


def get_user_by_email(email: str) -> dict | None:
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, email, created_at FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None


# ── Messages ───────────────────────────────────────────────────────
def save_message(user_id: int | None, text: str, result: dict, channel: str = "web") -> dict:
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """INSERT INTO messages
               (user_id, message_text, risk_score, classification, patterns, recommendation, channel)
               VALUES (%s, %s, %s, %s, %s, %s, %s)
               RETURNING id, analyzed_at""",
            (user_id, text, result["risk_score"], result["classification"],
             result["patterns_detected"], result["recommendation"], channel),
        )
        row = cur.fetchone()
        return {"id": row["id"], "analyzed_at": row["analyzed_at"]}


def get_user_history(user_id: int, limit: int = 20, offset: int = 0) -> list:
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """SELECT id, message_text, risk_score, classification,
                      patterns, recommendation, channel, analyzed_at
               FROM messages WHERE user_id = %s
               ORDER BY analyzed_at DESC LIMIT %s OFFSET %s""",
            (user_id, limit, offset),
        )
        return [dict(r) for r in cur.fetchall()]


def delete_message(message_id: int, user_id: int) -> bool:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM messages WHERE id = %s AND user_id = %s",
            (message_id, user_id),
        )
        return cur.rowcount > 0


def get_user_stats(user_id: int) -> dict:
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN classification='HIGH RISK'   THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN classification='MEDIUM RISK' THEN 1 ELSE 0 END) AS medium,
                SUM(CASE WHEN classification='LOW RISK'    THEN 1 ELSE 0 END) AS low,
                ROUND(AVG(risk_score)::numeric, 1) AS avg_score
               FROM messages WHERE user_id = %s""",
            (user_id,),
        )
        row = cur.fetchone()
        return dict(row)


# ── Rate limiting (SMS channel) ────────────────────────────────────
def sms_rate_check(phone: str, limit: int = 10, hours: int = 1) -> tuple[bool, int]:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """SELECT COUNT(*) FROM messages
               WHERE message_text LIKE %s
               AND channel = 'sms'
               AND analyzed_at > NOW() - INTERVAL '%s hours'""",
            (f"%{phone}%", hours),
        )
        count = cur.fetchone()[0]
        return count >= limit, count
