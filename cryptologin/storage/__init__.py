"""
CryptoLogin Storage Package
"""
from .base import StorageInterface, UserRecord
from .memory import MemoryStorage
from .sqlite import SQLiteStorage
from .sqlite_v2 import SQLiteStorageV2

__all__ = [
    'StorageInterface',
    'UserRecord',
    'MemoryStorage',
    'SQLiteStorage',
    'SQLiteStorageV2'
]