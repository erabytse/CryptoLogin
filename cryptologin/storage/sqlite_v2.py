"""
CryptoLogin SQLite Storage - V2 with Zero-Knowledge fields
"""
import json
import sqlite3
import logging
import os
from typing import Optional, Dict, Any, List
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path

from .base import StorageInterface, UserRecord

logger = logging.getLogger(__name__)


class SQLiteStorageV2(StorageInterface):
    """
    SQLite Storage - V2 with Zero-Knowledge fields.
    """
    
    # V2 Schema
    CREATE_TABLE_QUERY = """
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        challenge_token TEXT,
        challenge TEXT,
        salt TEXT,
        user_data TEXT DEFAULT '{}',
        vault_data TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_activity_at DATETIME
    );
    """
    
    MIGRATE_ADD_CHALLENGE = """
    ALTER TABLE users ADD COLUMN challenge TEXT;
    """
    
    MIGRATE_ADD_SALT = """
    ALTER TABLE users ADD COLUMN salt TEXT;
    """
    
    MIGRATE_COPY_DATA = """
    UPDATE users SET challenge = challenge_token WHERE challenge IS NULL;
    """
    
    CREATE_INDEXES = [
        "CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id);",
        "CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);",
        "CREATE INDEX IF NOT EXISTS idx_users_last_activity ON users(last_activity_at);",
    ]
    
    # Queries
    INSERT_QUERY = """
    INSERT OR REPLACE INTO users (
        user_id, challenge_token, challenge, salt, user_data, vault_data,
        created_at, updated_at, last_activity_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    
    SELECT_QUERY = """
    SELECT user_id, challenge_token, challenge, salt, user_data, vault_data,
           created_at, updated_at, last_activity_at
    FROM users WHERE user_id = ?
    """
    
    SELECT_EXISTS_QUERY = "SELECT 1 FROM users WHERE user_id = ? LIMIT 1"
    DELETE_QUERY = "DELETE FROM users WHERE user_id = ?"
    UPDATE_ACTIVITY_QUERY = "UPDATE users SET last_activity_at = ? WHERE user_id = ?"
    COUNT_QUERY = "SELECT COUNT(*) FROM users"
    
    LIST_QUERY = """
    SELECT user_id, created_at, updated_at, last_activity_at, vault_data
    FROM users
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
    """
    
    def __init__(self, db_path: str = "cryptologin_v2.db", auto_migrate: bool = True):
        self.db_path = db_path
        self._ensure_directory_exists()
        
        if auto_migrate:
            self.migrate()
        
        logger.info("SQLiteStorage V2 initialized with database: %s", db_path)
    
    def _ensure_directory_exists(self) -> None:
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    
    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(
            self.db_path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        conn.row_factory = sqlite3.Row
        
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA cache_size = 10000")
            conn.execute("PRAGMA temp_store = MEMORY")
            
            yield conn
        finally:
            conn.close()
    
    def migrate(self) -> None:
        """Migrate database to V2 schema."""
        logger.info("Running V2 migration...")
        
        try:
            with self._get_connection() as conn:
                # 1. Create table if not exists
                conn.execute(self.CREATE_TABLE_QUERY)
                
                # 2. Check if columns exist and add them if needed
                cursor = conn.execute("PRAGMA table_info(users)")
                columns = [row['name'] for row in cursor.fetchall()]
                
                if 'challenge' not in columns:
                    logger.info("Adding 'challenge' column...")
                    conn.execute(self.MIGRATE_ADD_CHALLENGE)
                
                if 'salt' not in columns:
                    logger.info("Adding 'salt' column...")
                    conn.execute(self.MIGRATE_ADD_SALT)
                
                # 3. Migrate existing data
                if 'challenge' in columns:
                    conn.execute(self.MIGRATE_COPY_DATA)
                
                # 4. Create indexes
                for index in self.CREATE_INDEXES:
                    conn.execute(index)
                
                conn.commit()
                logger.info("V2 migration completed successfully")
                
        except sqlite3.Error as e:
            logger.error("Migration failed: %s", e)
            raise
    
    # ============================================================
    # IMPLÉMENTATION DE StorageInterface
    # ============================================================
    
    def save_user(self, record: UserRecord) -> None:
        logger.debug("Saving user (V2): %s...", record.user_id[:16])
        
        try:
            with self._get_connection() as conn:
                vault_json = json.dumps(record.vault_data) if record.vault_data else None
                user_data_json = json.dumps(record.user_data)
                
                conn.execute(
                    self.INSERT_QUERY,
                    (
                        record.user_id,
                        record.challenge_token,
                        record.challenge,
                        record.salt,
                        user_data_json,
                        vault_json,
                        record.created_at.isoformat(),
                        record.updated_at.isoformat(),
                        record.last_activity_at.isoformat() if record.last_activity_at else None
                    )
                )
                conn.commit()
                logger.debug("User saved successfully (V2): %s...", record.user_id[:16])
                
        except sqlite3.Error as e:
            logger.error("Failed to save user: %s", e)
            raise
    
    def get_user(self, user_id: str) -> Optional[UserRecord]:
        logger.debug("Getting user (V2): %s...", user_id[:16])
        
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(self.SELECT_QUERY, (user_id,))
                row = cursor.fetchone()
                
                if not row:
                    logger.debug("User not found: %s...", user_id[:16])
                    return None
                
                user_data = json.loads(row['user_data']) if row['user_data'] else {}
                vault_data = json.loads(row['vault_data']) if row['vault_data'] else None
                
                record = UserRecord(
                    user_id=row['user_id'],
                    challenge_token=row['challenge_token'],
                    challenge=row['challenge'],
                    salt=row['salt'],
                    created_at=datetime.fromisoformat(row['created_at']),
                    updated_at=datetime.fromisoformat(row['updated_at']),
                    user_data=user_data,
                    vault_data=vault_data,
                    last_activity_at=datetime.fromisoformat(row['last_activity_at']) 
                                    if row['last_activity_at'] else None
                )
                
                logger.debug("User retrieved (V2): %s...", user_id[:16])
                return record
                
        except sqlite3.Error as e:
            logger.error("Failed to get user: %s", e)
            raise
    
    def user_exists(self, user_id: str) -> bool:
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(self.SELECT_EXISTS_QUERY, (user_id,))
                return cursor.fetchone() is not None
        except sqlite3.Error as e:
            logger.error("Failed to check user existence: %s", e)
            raise
    
    def delete_user(self, user_id: str) -> bool:
        logger.debug("Deleting user (V2): %s...", user_id[:16])
        
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(self.DELETE_QUERY, (user_id,))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error("Failed to delete user: %s", e)
            raise
    
    def update_user_activity(self, user_id: str) -> None:
        try:
            with self._get_connection() as conn:
                now = datetime.now().isoformat()
                conn.execute(self.UPDATE_ACTIVITY_QUERY, (now, user_id))
                conn.commit()
        except sqlite3.Error as e:
            logger.error("Failed to update activity: %s", e)
            raise
    
    def get_user_count(self) -> int:
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(self.COUNT_QUERY)
                return cursor.fetchone()[0]
        except sqlite3.Error as e:
            logger.error("Failed to get user count: %s", e)
            raise
    
    def list_users(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(self.LIST_QUERY, (limit, offset))
                rows = cursor.fetchall()
                
                users = []
                for row in rows:
                    user_data = {
                        'user_id': row['user_id'],
                        'created_at': datetime.fromisoformat(row['created_at']),
                        'updated_at': datetime.fromisoformat(row['updated_at']),
                        'last_activity_at': datetime.fromisoformat(row['last_activity_at']) 
                                         if row['last_activity_at'] else None,
                        'has_vault': row['vault_data'] is not None
                    }
                    users.append(user_data)
                    
                return users
        except sqlite3.Error as e:
            logger.error("Failed to list users: %s", e)
            raise
    
    def backup(self, backup_path: str) -> bool:
        try:
            if not os.path.exists(self.db_path):
                logger.warning("Database file does not exist, creating empty backup")
                Path(backup_path).parent.mkdir(parents=True, exist_ok=True)
                with open(backup_path, 'w') as f:
                    pass
                return True
            
            with self._get_connection() as conn:
                backup_conn = sqlite3.connect(backup_path)
                conn.backup(backup_conn)
                backup_conn.close()
                return True
        except Exception as e:
            logger.error("Backup failed: %s", e)
            return False
    
    def vacuum(self) -> bool:
        try:
            with self._get_connection() as conn:
                conn.execute("VACUUM")
                return True
        except sqlite3.Error as e:
            logger.error("Vacuum failed: %s", e)
            return False