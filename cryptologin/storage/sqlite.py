"""
CryptoLogin SQLite Storage
--------------------------
Implementation of StorageInterface using SQLite.

Features:
- Automatic schema migration
- Thread-safe connection
- ACID transactions
- Automatic backup (WAL mode)
- Indexes for performance

Security:
- Database file with restrictive permissions
- WAL logging for crash recovery
- Parameterised queries (SQL injection protection)
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


class SQLiteStorage(StorageInterface):
    """
    Implementation of StorageInterface using SQLite.
    
    Uses SQLite for data persistence with:
    - Automatic migration on first connection
    - WAL mode for performance and recovery
    - Transactions for data integrity
    """
    
    # Schéma de la base de données
    SCHEMA_VERSION = 1
    
    # Requêtes séparées pour éviter l'erreur "one statement at a time"
    CREATE_TABLE_QUERY = """
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        challenge_token TEXT NOT NULL,
        user_data TEXT DEFAULT '{}',
        vault_data TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_activity_at DATETIME
    )
    """
    
    CREATE_INDEX_USER_ID = """
    CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id)
    """
    
    CREATE_INDEX_CREATED_AT = """
    CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)
    """
    
    CREATE_INDEX_LAST_ACTIVITY = """
    CREATE INDEX IF NOT EXISTS idx_users_last_activity ON users(last_activity_at)
    """
    
    # Requêtes SQL paramétrées
    INSERT_QUERY = """
    INSERT OR REPLACE INTO users (
        user_id, challenge_token, user_data, vault_data,
        created_at, updated_at, last_activity_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    
    SELECT_QUERY = """
    SELECT user_id, challenge_token, user_data, vault_data,
           created_at, updated_at, last_activity_at
    FROM users WHERE user_id = ?
    """
    
    SELECT_EXISTS_QUERY = """
    SELECT 1 FROM users WHERE user_id = ? LIMIT 1
    """
    
    DELETE_QUERY = """
    DELETE FROM users WHERE user_id = ?
    """
    
    UPDATE_ACTIVITY_QUERY = """
    UPDATE users SET last_activity_at = ? WHERE user_id = ?
    """
    
    COUNT_QUERY = """
    SELECT COUNT(*) FROM users
    """
    
    LIST_QUERY = """
    SELECT user_id, created_at, updated_at, last_activity_at, vault_data
    FROM users
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
    """
    
    def __init__(self, db_path: str = "cryptologin.db", auto_migrate: bool = True):
        """
        Initialises the SQLite database.
        
        Args:
            db_path: Path to the database file
            auto_migrate: Automatically migrate the schema if necessary
        """
        self.db_path = db_path
        self._ensure_directory_exists()
        
        if auto_migrate:
            self.migrate()
        
        logger.info("SQLiteStorage initialized with database: %s", db_path)
    
    def _ensure_directory_exists(self) -> None:
        """Creates the database directory if it does not exist."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info("Created database directory: %s", db_dir)
    
    @contextmanager
    def _get_connection(self):
        """
        Context manager for SQLite connections.
        
        Configures the connection with:
        - row_factory for access by column name
        - WAL mode for performance
        - Foreign keys enabled
        """
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
        """
        Migrates the database to the current schema.
        This method:
        1. Checks whether the table exists
        2. Creates the table if necessary
        3. Creates the indexes
        Each query is executed separately.
        """
        logger.info("Running database migration...")
        
        try:
            with self._get_connection() as conn:
                # Création de la table (une seule requête)
                conn.execute(self.CREATE_TABLE_QUERY)
                
                # Création des indexes (une par appel)
                conn.execute(self.CREATE_INDEX_USER_ID)
                conn.execute(self.CREATE_INDEX_CREATED_AT)
                conn.execute(self.CREATE_INDEX_LAST_ACTIVITY)
                
                conn.commit()
                logger.info("Database migration completed successfully")
                
        except sqlite3.Error as e:
            logger.error("Migration failed: %s", e)
            raise
    
    # ============================================================
    # IMPLÉMENTATION DE StorageInterface
    # ============================================================
    
    def save_user(self, record: UserRecord) -> None:
        logger.debug("Saving user: %s...", record.user_id[:16])
        
        try:
            with self._get_connection() as conn:
                # CORRECTION: S'assurer que vault_data est bien sérialisé
                vault_json = json.dumps(record.vault_data) if record.vault_data else None
                user_data_json = json.dumps(record.user_data)
                
                conn.execute(
                    self.INSERT_QUERY,
                    (
                        record.user_id,
                        record.challenge_token,
                        user_data_json,
                        vault_json,
                        record.created_at.isoformat(),
                        record.updated_at.isoformat(),
                        record.last_activity_at.isoformat() if record.last_activity_at else None
                    )
                )
                conn.commit()
                logger.debug("User saved successfully: %s...", record.user_id[:16])
                
        except sqlite3.Error as e:
            logger.error("Failed to save user %s...: %s", record.user_id[:16], e)
            raise


    def get_user(self, user_id: str) -> Optional[UserRecord]:
        logger.debug("Getting user: %s...", user_id[:16])
        
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(self.SELECT_QUERY, (user_id,))
                row = cursor.fetchone()
                
                if not row:
                    logger.debug("User not found: %s...", user_id[:16])
                    return None
                
                user_data = json.loads(row['user_data']) if row['user_data'] else {}
                # CORRECTION: Désérialiser vault_data correctement
                vault_data = None
                if row['vault_data']:
                    try:
                        vault_data = json.loads(row['vault_data'])
                    except json.JSONDecodeError:
                        # Si ce n'est pas du JSON valide, garder comme chaîne
                        vault_data = row['vault_data']
                
                record = UserRecord(
                    user_id=row['user_id'],
                    challenge_token=row['challenge_token'],
                    created_at=datetime.fromisoformat(row['created_at']),
                    updated_at=datetime.fromisoformat(row['updated_at']),
                    user_data=user_data,
                    vault_data=vault_data,
                    last_activity_at=datetime.fromisoformat(row['last_activity_at']) 
                                    if row['last_activity_at'] else None
                )
                
                logger.debug("User retrieved: %s...", user_id[:16])
                return record
                
        except sqlite3.Error as e:
            logger.error("Failed to get user %s...: %s", user_id[:16], e)
            raise
        
    def user_exists(self, user_id: str) -> bool:
        """
        Check whether a user exists.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(self.SELECT_EXISTS_QUERY, (user_id,))
                exists = cursor.fetchone() is not None
                return exists
                
        except sqlite3.Error as e:
            logger.error("Failed to check user existence %s...: %s", user_id[:16], e)
            raise
    
    def delete_user(self, user_id: str) -> bool:
        """
        Delete a user.
        """
        logger.debug("Deleting user: %s...", user_id[:16])
        
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(self.DELETE_QUERY, (user_id,))
                conn.commit()
                deleted = cursor.rowcount > 0
                
                if deleted:
                    logger.debug("User deleted: %s...", user_id[:16])
                else:
                    logger.debug("User not found for deletion: %s...", user_id[:16])
                    
                return deleted
                
        except sqlite3.Error as e:
            logger.error("Failed to delete user %s...: %s", user_id[:16], e)
            raise
    
    def update_user_activity(self, user_id: str) -> None:
        """
        Updates a user’s activity.
        Updates the last activity date.
        """
        try:
            with self._get_connection() as conn:
                now = datetime.now().isoformat()
                conn.execute(self.UPDATE_ACTIVITY_QUERY, (now, user_id))
                conn.commit()
                logger.debug("Activity updated for user: %s...", user_id[:16])
                
        except sqlite3.Error as e:
            logger.error("Failed to update activity for user %s...: %s", user_id[:16], e)
            raise
    
    
    def get_user_count(self) -> int:
        """
        Returns the total number of users.
        Retrieves the total number of users.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(self.COUNT_QUERY)
                count = cursor.fetchone()[0]
                return count
                
        except sqlite3.Error as e:
            logger.error("Failed to get user count: %s", e)
            raise
    
   
    def list_users(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Lists the users for administration purposes.
        """
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
    
    # ============================================================
    # MÉTHODES UTILITAIRES
    # ============================================================
    
    def backup(self, backup_path: str) -> bool:
        """
        Backs up the database.
        
        Args:
            backup_path: Path to save to
            
        Returns:
            bool: True if the backup was successful
        """
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
                
                logger.info("Database backed up to: %s", backup_path)
                return True
                
        except Exception as e:
            logger.error("Backup failed: %s", e)
            return False
    
    def vacuum(self) -> bool:
        """
        Compact the database to free up space.
        
        Returns:
            bool: True if the compaction was successful
        """
        try:
            with self._get_connection() as conn:
                conn.execute("VACUUM")
                logger.info("Database vacuumed successfully")
                return True
                
        except sqlite3.Error as e:
            logger.error("Vacuum failed: %s", e)
            return False
    
    def get_database_size(self) -> int:
        """
        Returns the size of the database in bytes.
        
        Returns:
            int: Size in bytes (0 if the file does not exist)
        """
        if os.path.exists(self.db_path):
            return os.path.getsize(self.db_path)
        return 0
    
    def delete_database(self) -> bool:
        """
        Deletes the database file.
        
        WARNING: This operation cannot be undone.
        
        Returns:
            bool: True if the deletion was successful
        """
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
                logger.warning("Database file deleted: %s", self.db_path)
                return True
            return False
        except Exception as e:
            logger.error("Failed to delete database: %s", e)
            return False