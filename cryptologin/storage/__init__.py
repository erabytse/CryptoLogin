"""
Package de stockage CryptoLogin
"""
from .base import StorageInterface, UserRecord
from .memory import MemoryStorage
from .sqlite import SQLiteStorage

__all__ = [
    'StorageInterface',
    'UserRecord',
    'MemoryStorage',
    'SQLiteStorage'
]