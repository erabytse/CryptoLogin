"""
Implémentation de stockage en mémoire (pour les tests)
"""
from typing import Optional, Dict, Any, List
from datetime import datetime

from .base import StorageInterface, UserRecord


class MemoryStorage(StorageInterface):
    """
    Stockage en mémoire pour les tests.
    
    Attention : Non persistant, à utiliser uniquement en développement.
    """
    
    def __init__(self):
        self._users: Dict[str, UserRecord] = {}
    
    def save_user(self, record: UserRecord) -> None:
        """Sauvegarde un utilisateur en mémoire."""
        self._users[record.user_id] = record
    
    def get_user(self, user_id: str) -> Optional[UserRecord]:
        """Récupère un utilisateur par son ID."""
        return self._users.get(user_id)
    
    def user_exists(self, user_id: str) -> bool:
        """Vérifie si un utilisateur existe."""
        return user_id in self._users
    
    def delete_user(self, user_id: str) -> bool:
        """Supprime un utilisateur."""
        if user_id in self._users:
            del self._users[user_id]
            return True
        return False
    
    def update_user_activity(self, user_id: str) -> None:
        """Met à jour la date de dernière activité."""
        record = self._users.get(user_id)
        if record:
            record.last_activity_at = datetime.now()
    
    def get_user_count(self) -> int:
        """Retourne le nombre total d'utilisateurs."""
        return len(self._users)
    
    def list_users(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Liste les utilisateurs."""
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
                'has_vault': record.vault_data is not None
            })
        return users