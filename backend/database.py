"""
PhishGuard AI - Database Module
Handles both Web (authenticated users) and SMS (anonymous) channels
"""

import os
from contextlib import contextmanager
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "database": os.getenv("DB_NAME", "phishguard"),
    "user":     os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", "password"),
    "port":     int(os.getenv("DB_PORT", "5432")),
}


@contextmanager
def get_conn():
    """Context manager for database connections"""
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
    """Initialize database schema for both web and SMS channels"""
    with get_conn() as conn:
        cur = conn.cursor()
        
        # Web users table (authenticated)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                email         VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at    TIMESTAMP DEFAULT NOW()
            );
        """)
        
        # SMS phone numbers table (anonymous)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS phone_numbers (
                id               SERIAL PRIMARY KEY,
                phone_number     VARCHAR(20) UNIQUE NOT NULL,
                first_seen       TIMESTAMP DEFAULT NOW(),
                last_activity    TIMESTAMP DEFAULT NOW(),
                total_messages   INTEGER DEFAULT 0,
                high_risk_count  INTEGER DEFAULT 0,
                medium_risk_count INTEGER DEFAULT 0,
                low_risk_count   INTEGER DEFAULT 0
            );
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_phone_number 
            ON phone_numbers(phone_number);
        """)
        
        # Messages table (handles both web and SMS)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id             SERIAL PRIMARY KEY,
                user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
                phone_id       INTEGER REFERENCES phone_numbers(id) ON DELETE SET NULL,
                message_text   TEXT NOT NULL,
                risk_score     INTEGER NOT NULL,
                classification VARCHAR(20) NOT NULL,
                patterns       TEXT[],
                recommendation TEXT,
                channel        VARCHAR(10) DEFAULT 'web',
                message_sid    VARCHAR(34),
                analyzed_at    TIMESTAMP DEFAULT NOW()
            );
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_user
            ON messages(user_id, analyzed_at DESC);
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_phone
            ON messages(phone_id, analyzed_at DESC);
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_classification
            ON messages(classification);
        """)

# WEB USERS (Authenticated)

def create_user(email: str, password_hash: str) -> dict:
    """Create a new web user account"""
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id, email, created_at",
            (email, password_hash),
        )
        return dict(cur.fetchone())


def get_user_by_email(email: str) -> dict | None:
    """Get user by email address"""
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    """Get user by ID"""
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, email, created_at FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None

# SMS PHONE NUMBERS (Anonymous)

def get_or_create_phone_number(phone: str) -> int:
    """
    Get existing phone_id or create new phone_number record.
    Returns: phone_id (int)
    """
    with get_conn() as conn:
        cur = conn.cursor()
        
        # Check if exists
        cur.execute(
            "SELECT id FROM phone_numbers WHERE phone_number = %s",
            (phone,)
        )
        result = cur.fetchone()
        
        if result:
            return result[0]
        
        # Create new
        cur.execute(
            """INSERT INTO phone_numbers (phone_number) 
               VALUES (%s) RETURNING id""",
            (phone,)
        )
        return cur.fetchone()[0]


def get_phone_stats(phone: str) -> dict | None:
    """
    Get analytics for a phone number.
    Returns: {total_analyzed, high_risk_count, medium_risk_count, low_risk_count, avg_risk_score}
    """
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """SELECT 
                total_messages, 
                high_risk_count, 
                medium_risk_count, 
                low_risk_count,
                first_seen, 
                last_activity,
                COALESCE(
                    (SELECT ROUND(AVG(risk_score)::numeric, 1) 
                     FROM messages m 
                     WHERE m.phone_id = p.id), 
                    0
                ) as avg_risk_score
               FROM phone_numbers p
               WHERE phone_number = %s""",
            (phone,)
        )
        row = cur.fetchone()
        return dict(row) if row else None


def update_phone_stats(phone_id: int, classification: str) -> None:
    """Update phone number statistics after analyzing a message"""
    with get_conn() as conn:
        cur = conn.cursor()
        
        # Determine which counter to increment
        count_field = classification.lower().replace(' ', '_') + '_count'
        
        cur.execute(
            f"""UPDATE phone_numbers 
                SET total_messages = total_messages + 1,
                    {count_field} = {count_field} + 1,
                    last_activity = NOW()
                WHERE id = %s""",
            (phone_id,)
        )

# MESSAGES (Both Web and SMS)

def save_message(
    user_id: int | None, 
    text: str, 
    result: dict, 
    channel: str = "web",
    message_sid: str | None = None,
    phone_id: int | None = None
) -> dict:
    """
    Save message analysis for either web or SMS channel.
    
    Args:
        user_id: Web user ID (None for SMS)
        text: Message content
        result: Analysis result from detect.py
        channel: 'web' or 'sms'
        message_sid: Twilio message ID (for SMS only)
        phone_id: Phone number ID (for SMS only)
    """
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """INSERT INTO messages
               (user_id, phone_id, message_text, risk_score, classification, 
                patterns, recommendation, channel, message_sid)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id, analyzed_at""",
            (user_id, phone_id, text, result["risk_score"], result["classification"],
             result["patterns_detected"], result["recommendation"], channel, message_sid),
        )
        row = cur.fetchone()
        return {"id": row["id"], "analyzed_at": row["analyzed_at"]}


def save_sms_message(phone: str, message_sid: str, body: str, analysis: dict) -> dict:
    """
    Save SMS message and update phone statistics.
    Convenience function for SMS channel.
    """
    phone_id = get_or_create_phone_number(phone)
    
    # Save message
    result = save_message(
        user_id=None,
        text=body,
        result=analysis,
        channel='sms',
        message_sid=message_sid,
        phone_id=phone_id
    )
    
    # Update phone stats
    update_phone_stats(phone_id, analysis['classification'])
    
    return result


def get_user_history(user_id: int, limit: int = 20, offset: int = 0) -> list:
    """Get message history for a web user"""
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


def get_phone_history(phone: str, limit: int = 20) -> list:
    """Get message history for a phone number"""
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """SELECT m.id, m.message_text, m.risk_score, m.classification,
                      m.patterns, m.recommendation, m.analyzed_at
               FROM messages m
               JOIN phone_numbers p ON m.phone_id = p.id
               WHERE p.phone_number = %s
               ORDER BY m.analyzed_at DESC LIMIT %s""",
            (phone, limit),
        )
        return [dict(r) for r in cur.fetchall()]


def delete_message(message_id: int, user_id: int) -> bool:
    """Delete a message (web users only)"""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM messages WHERE id = %s AND user_id = %s",
            (message_id, user_id),
        )
        return cur.rowcount > 0


def get_user_stats(user_id: int) -> dict:
    """Get statistics for a web user"""
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

# RATE LIMITING

def check_sms_rate_limit(phone: str, hourly_limit: int = 10, daily_limit: int = 100) -> dict:
    """
    Check if phone number has exceeded SMS rate limits.
    Returns: {allowed: bool, reason: str, hourly_count: int, daily_count: int}
    """
    with get_conn() as conn:
        cur = conn.cursor()
        
        # Get phone_id
        phone_id = get_or_create_phone_number(phone)
        
        # Check hourly limit
        cur.execute(
            """SELECT COUNT(*) FROM messages
               WHERE phone_id = %s
               AND channel = 'sms'
               AND analyzed_at > NOW() - INTERVAL '1 hour'""",
            (phone_id,)
        )
        hourly_count = cur.fetchone()[0]
        
        # Check daily limit
        cur.execute(
            """SELECT COUNT(*) FROM messages
               WHERE phone_id = %s
               AND channel = 'sms'
               AND analyzed_at > NOW() - INTERVAL '1 day'""",
            (phone_id,)
        )
        daily_count = cur.fetchone()[0]
        
        # Determine if allowed
        if hourly_count >= hourly_limit:
            return {
                'allowed': False,
                'reason': f'Hourly limit exceeded ({hourly_count}/{hourly_limit})',
                'hourly_count': hourly_count,
                'daily_count': daily_count
            }
        
        if daily_count >= daily_limit:
            return {
                'allowed': False,
                'reason': f'Daily limit exceeded ({daily_count}/{daily_limit})',
                'hourly_count': hourly_count,
                'daily_count': daily_count
            }
        
        return {
            'allowed': True,
            'reason': 'OK',
            'hourly_count': hourly_count,
            'daily_count': daily_count
        }


def sms_rate_check(phone: str, limit: int = 10, hours: int = 1) -> tuple[bool, int]:
    """
    Legacy function for basic rate checking (kept for compatibility).
    Returns: (exceeded: bool, count: int)
    """
    with get_conn() as conn:
        cur = conn.cursor()
        
        # Get phone_id
        cur.execute(
            "SELECT id FROM phone_numbers WHERE phone_number = %s",
            (phone,)
        )
        result = cur.fetchone()
        
        if not result:
            return False, 0
        
        phone_id = result[0]
        
        cur.execute(
            """SELECT COUNT(*) FROM messages
               WHERE phone_id = %s
               AND channel = 'sms'
               AND analyzed_at > NOW() - INTERVAL '%s hours'""",
            (phone_id, hours),
        )
        count = cur.fetchone()[0]
        return count >= limit, count