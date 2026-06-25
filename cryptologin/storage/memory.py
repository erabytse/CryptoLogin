"""
In-memory storage implementation – V2 with zero-knowledge fields
"""
from typing import Optional, Dict, Any, List
from datetime import datetime

from .base import StorageInterface, UserRecord


class MemoryStorage(StorageInterface):
    """
    In-memory storage for testing – V2.
    
    Please note: Non-persistent; for development use only.
    """
    
    def __init__(self):
        self._users: Dict[str, UserRecord] = {}
    
    def save_user(self, record: UserRecord) -> None:
        """Saves a user to memory."""
        self._users[record.user_id] = record
    
    def get_user(self, user_id: str) -> Optional[UserRecord]:
        """Retrieves a user by their ID."""
        return self._users.get(user_id)
    
    def user_exists(self, user_id: str) -> bool:
        """Checks whether a user exists."""
        return user_id in self._users
    
    def delete_user(self, user_id: str) -> bool:
        """Delete a user."""
        if user_id in self._users:
            del self._users[user_id]
            return True
        return False
    
    def update_user_activity(self, user_id: str) -> None:
        """Updates the last activity date."""
        record = self._users.get(user_id)
        if record:
            record.last_activity_at = datetime.now()
    
    def get_user_count(self) -> int:
        """Returns the total number of users."""
        return len(self._users)
    
    def list_users(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List of users."""
        users = []
        for i, (user_id, record) in enumerate(self._users.items()):
            if i < offset:
                continue
            if len(users) >= limit:
                break
            users.append({
                'user_id': user_id,
                'created_at': record.created_at,
                'updated_at': record.updated_at,
                'last_activity_at': record.last_activity_at,
                'has_vault': record.vault_data is not None,
                'has_salt': record.salt is not None,
            })
        return users