"""
Interfaces de stockage abstraites
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime


@dataclass
class UserRecord:
    """
    Enregistrement d'un utilisateur en base de données.
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
    Interface de stockage pour CryptoLogin.
    
    Toute implémentation de stockage (SQLite, PostgreSQL, Memory, etc.)
    doit implémenter cette interface.
    """
    
    @abstractmethod
    def save_user(self, record: UserRecord) -> None:
        """
        Sauvegarde ou met à jour un utilisateur.
        
        Args:
            record: L'enregistrement à sauvegarder
        """
        pass
    
    @abstractmethod
    def get_user(self, user_id: str) -> Optional[UserRecord]:
        """
        Récupère un utilisateur par son ID.
        
        Args:
            user_id: L'ID de l'utilisateur
            
        Returns:
            Optional[UserRecord]: L'utilisateur ou None
        """
        pass
    
    @abstractmethod
    def user_exists(self, user_id: str) -> bool:
        """
        Vérifie si un utilisateur existe.
        
        Args:
            user_id: L'ID de l'utilisateur
            
        Returns:
            bool: True si l'utilisateur existe
        """
        pass
    
    @abstractmethod
    def delete_user(self, user_id: str) -> bool:
        """
        Supprime un utilisateur.
        
        Args:
            user_id: L'ID de l'utilisateur
            
        Returns:
            bool: True si la suppression a réussi
        """
        pass
    
    @abstractmethod
    def update_user_activity(self, user_id: str) -> None:
        """
        Met à jour la date de dernière activité.
        
        Args:
            user_id: L'ID de l'utilisateur
        """
        pass
    
    @abstractmethod
    def get_user_count(self) -> int:
        """
        Retourne le nombre total d'utilisateurs.
        
        Returns:
            int: Nombre d'utilisateurs
        """
        pass
    
    @abstractmethod
    def list_users(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Liste les utilisateurs pour l'administration.
        
        Args:
            limit: Nombre maximum d'utilisateurs
            offset: Décalage
            
        Returns:
            List[Dict[str, Any]]: Liste des utilisateurs
        """
        pass