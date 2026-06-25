"""
Abstract Storage Interfaces – V2 with Zero-Knowledge Fields
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime


@dataclass
class UserRecord:
    """
    User registration – V2 with zero-knowledge fields.
    
    V2 adds:
    - challenge: Plaintext challenge for HMAC
    - salt: Salt for key derivation
    """
    user_id: str
    created_at: datetime
    updated_at: datetime
    
    # V1 fields (for backwards compatibility)
    challenge_token: Optional[str] = None  # V1: Numerical challenge
    
    # V2 fields (Zero-Knowledge)
    challenge: Optional[str] = None  # V2: A plaintext challenge for HMAC
    salt: Optional[str] = None  # V2: Salt for key derivation
    
    # Data
    user_data: Dict[str, Any] = field(default_factory=dict)
    vault_data: Optional[str] = None
    last_activity_at: Optional[datetime] = None


class StorageInterface(ABC):
    """
    Storage interface for CryptoLogin.
    
    Any storage implementation must implement this interface.
    """
    
    @abstractmethod
    def save_user(self, record: UserRecord) -> None:
        """Saves or updates a user."""
        pass
    
    @abstractmethod
    def get_user(self, user_id: str) -> Optional[UserRecord]:
        """Retrieves a user by their ID."""
        pass
    
    @abstractmethod
    def user_exists(self, user_id: str) -> bool:
        """Check whether a user exists."""
        pass
    
    @abstractmethod
    def delete_user(self, user_id: str) -> bool:
        """Delete a user."""
        pass
    
    @abstractmethod
    def update_user_activity(self, user_id: str) -> None:
        """Updates the last activity date."""
        pass
    
    @abstractmethod
    def get_user_count(self) -> int:
        """Returns the total number of users."""
        pass
    
    @abstractmethod
    def list_users(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List of users for administration purposes."""
        pass