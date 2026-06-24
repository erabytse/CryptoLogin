"""
Abstract storage interfaces
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime


@dataclass
class UserRecord:
    """
    Registering a user in the database.
    """
    user_id: str
    challenge_token: str  # Challenge chiffré
    created_at: datetime
    updated_at: datetime
    user_data: Dict[str, Any] = field(default_factory=dict)
    vault_data: Optional[str] = None  # VaultRecord sérialisé (encrypted_data)
    last_activity_at: Optional[datetime] = None


class StorageInterface(ABC):
    """
    Storage interface for CryptoLogin.
    
    Any storage implementation (SQLite, PostgreSQL, Memory, etc.)
    must implement this interface.
    """
    
    @abstractmethod
    def save_user(self, record: UserRecord) -> None:
        """
        Saves or updates a user.
        
        Args:
            record: The record to be saved
        """
        pass
    
    @abstractmethod
    def get_user(self, user_id: str) -> Optional[UserRecord]:
        """
        Retrieves a user by their ID.
        
        Args:
            user_id: The user’s ID
            
        Returns:
            Optional[UserRecord]: The user or None
        """
        pass
    
    @abstractmethod
    def user_exists(self, user_id: str) -> bool:
        """
        Checks whether a user exists.
        
        Args:
            user_id: The user’s ID
            
        Returns:
            bool: True if the user exists
        """
        pass
    
    @abstractmethod
    def delete_user(self, user_id: str) -> bool:
        """
        Deletes a user.
        
        Args:
            user_id: The user’s ID
            
        Returns:
            bool: True if the deletion was successful
        """
        pass
    
    @abstractmethod
    def update_user_activity(self, user_id: str) -> None:
        """
        Updates the last activity date.
        
        Args:
            user_id: The user’s ID
        """
        pass
    
    @abstractmethod
    def get_user_count(self) -> int:
        """
        Returns the total number of users.
        
        Returns:
            int: Number of users
        """
        pass
    
    @abstractmethod
    def list_users(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Lists the users for administration purposes.
        
        Args:
            limit: Maximum number of users
            offset: Offset
            
        Returns:
            List[Dict[str, Any]]: List of users
        """
        pass