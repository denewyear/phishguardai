"""
PhishGuard Web - Database Module
Web-based phishing detection platform with authenticated users
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
    """Initialize database schema for web application"""
    with get_conn() as conn:
        cur = conn.cursor()
        
        # Users table (authenticated web users)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                email         VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at    TIMESTAMP DEFAULT NOW()
            );
        """)
        
        # Messages table (all phishing analyses)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id             SERIAL PRIMARY KEY,
                user_id        INTEGER REFERENCES users(id) ON DELETE CASCADE,
                message_text   TEXT NOT NULL,
                risk_score     INTEGER NOT NULL,
                classification VARCHAR(20) NOT NULL,
                patterns       TEXT[],
                recommendation TEXT,
                analyzed_at    TIMESTAMP DEFAULT NOW()
            );
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_user
            ON messages(user_id, analyzed_at DESC);
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_classification
            ON messages(classification);
        """)
        
        # Shared phishing examples table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS shared_phishes (
                id                SERIAL PRIMARY KEY,
                message_id        INTEGER REFERENCES messages(id) ON DELETE CASCADE,
                shared_by_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                title             VARCHAR(255),
                description       TEXT,
                is_public         BOOLEAN DEFAULT TRUE,
                shared_at         TIMESTAMP DEFAULT NOW()
            );
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_shared_public
            ON shared_phishes(is_public, shared_at DESC);
        """)

# USER MANAGEMENT

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

# MESSAGE ANALYSIS

def save_message(user_id: int, text: str, result: dict) -> dict:
    """
    Save message analysis for a web user.
    
    Args:
        user_id: Web user ID
        text: Message content
        result: Analysis result from detect.py containing:
                {risk_score, classification, patterns_detected, recommendation}
    
    Returns:
        {id, analyzed_at}
    """
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """INSERT INTO messages
               (user_id, message_text, risk_score, classification, patterns, recommendation)
               VALUES (%s, %s, %s, %s, %s, %s)
               RETURNING id, analyzed_at""",
            (user_id, text, result["risk_score"], result["classification"],
             result["patterns_detected"], result["recommendation"]),
        )
        row = cur.fetchone()
        return {"id": row["id"], "analyzed_at": row["analyzed_at"]}


def get_user_history(user_id: int, limit: int = 20, offset: int = 0) -> list:
    """Get message history for a web user"""
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """SELECT id, message_text, risk_score, classification,
                      patterns, recommendation, analyzed_at
               FROM messages WHERE user_id = %s
               ORDER BY analyzed_at DESC LIMIT %s OFFSET %s""",
            (user_id, limit, offset),
        )
        return [dict(r) for r in cur.fetchall()]


def delete_message(message_id: int, user_id: int) -> bool:
    """Delete a message"""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM messages WHERE id = %s AND user_id = %s",
            (message_id, user_id),
        )
        return cur.rowcount > 0


def get_user_stats(user_id: int) -> dict:
    """
    Get statistics for a web user.
    
    Returns:
        {total, high, medium, low, avg_score}
    """
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

# TRENDING & ANALYTICS

def get_trending_patterns(limit: int = 10, days: int = 7) -> list:
    """
    Get most common phishing patterns from recent analyses.
    
    Args:
        limit: Number of top patterns to return
        days: Look back period in days
    
    Returns:
        List of {pattern, count, percentage}
    """
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """SELECT 
                UNNEST(patterns) as pattern,
                COUNT(*) as count,
                ROUND((COUNT(*)::numeric / 
                    (SELECT COUNT(*) FROM messages 
                     WHERE analyzed_at > NOW() - INTERVAL '%s days' 
                     AND classification = 'HIGH RISK')) * 100, 1) as percentage
               FROM messages
               WHERE analyzed_at > NOW() - INTERVAL '%s days'
               AND classification = 'HIGH RISK'
               GROUP BY pattern
               ORDER BY count DESC
               LIMIT %s""",
            (days, days, limit),
        )
        return [dict(r) for r in cur.fetchall()]


def get_risk_distribution() -> dict:
    """
    Get distribution of risk levels across all analyses.
    
    Returns:
        {high_count, medium_count, low_count, total}
    """
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """SELECT
                COUNT(*) as total,
                SUM(CASE WHEN classification='HIGH RISK'   THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN classification='MEDIUM RISK' THEN 1 ELSE 0 END) AS medium_count,
                SUM(CASE WHEN classification='LOW RISK'    THEN 1 ELSE 0 END) AS low_count
               FROM messages"""
        )
        return dict(cur.fetchone())

# SHARING FEATURE

def share_phish(message_id: int, user_id: int, title: str = None, 
                description: str = None, is_public: bool = True) -> dict:
    """
    Share a phishing message to the public gallery.
    
    Args:
        message_id: ID of message to share
        user_id: User sharing the message
        title: Optional title for the shared phish
        description: Optional description/context
        is_public: Whether to make it publicly visible
    
    Returns:
        {id, shared_at}
    """
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """INSERT INTO shared_phishes
               (message_id, shared_by_user_id, title, description, is_public)
               VALUES (%s, %s, %s, %s, %s)
               RETURNING id, shared_at""",
            (message_id, user_id, title, description, is_public),
        )
        return dict(cur.fetchone())


def get_shared_phishes(limit: int = 20, offset: int = 0) -> list:
    """
    Get public shared phishing examples.
    
    Returns:
        List of shared phishes with message details
    """
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """SELECT 
                sp.id, sp.title, sp.description, sp.shared_at,
                m.message_text, m.risk_score, m.classification, m.patterns,
                u.email as shared_by
               FROM shared_phishes sp
               JOIN messages m ON sp.message_id = m.id
               JOIN users u ON sp.shared_by_user_id = u.id
               WHERE sp.is_public = TRUE
               ORDER BY sp.shared_at DESC
               LIMIT %s OFFSET %s""",
            (limit, offset),
        )
        return [dict(r) for r in cur.fetchall()]


def unshare_phish(shared_id: int, user_id: int) -> bool:
    """Remove a shared phish (only by the user who shared it)"""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM shared_phishes WHERE id = %s AND shared_by_user_id = %s",
            (shared_id, user_id),
        )
        return cur.rowcount > 0

def get_trending_patterns(limit=10, days=7):
    """Get most common phishing patterns from recent messages"""
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    UNNEST(patterns) as pattern,
                    COUNT(*) as count,
                    AVG(risk_score) as avg_risk
                FROM messages
                WHERE analyzed_at > NOW() - INTERVAL '%s days'
                GROUP BY pattern
                ORDER BY count DESC
                LIMIT %s
            """, (days, limit))
            return cur.fetchall()

def share_phish(message_id, user_id, title=None, description=None, is_public=True):
    """Share a phishing message to public gallery"""
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                INSERT INTO shared_phishes (message_id, shared_by_user_id, title, description, is_public)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, shared_at
            """, (message_id, user_id, title, description, is_public))
            return cur.fetchone()

def get_shared_phishes(limit=20, offset=0):
    """Get public shared phishing examples"""
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    sp.id,
                    sp.title,
                    sp.description,
                    sp.shared_at,
                    m.message_text,
                    m.risk_score,
                    m.classification,
                    m.patterns
                FROM shared_phishes sp
                JOIN messages m ON sp.message_id = m.id
                WHERE sp.is_public = TRUE
                ORDER BY sp.shared_at DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))
            return cur.fetchall()