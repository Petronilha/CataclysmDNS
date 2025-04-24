"""
Arquivo base para cache sem dependências circulares
"""
from enum import Enum
from typing import Optional

class CacheType(Enum):
    MEMORY = "memory"
    DISK = "disk"
    REDIS = "redis"
    SQLITE = "sqlite"


class CacheConfig:
    """Configuração básica do cache"""
    def __init__(
        self,
        cache_type=CacheType.MEMORY,
        ttl=3600,
        max_size=10000,
        redis_url=None,
        sqlite_path="cache.db",
        disk_path="cache_data",
        compression=True,
        serializer="json"
    ):
        self.cache_type = cache_type
        self.ttl = ttl
        self.max_size = max_size
        self.redis_url = redis_url
        self.sqlite_path = sqlite_path
        self.disk_path = disk_path
        self.compression = compression
        self.serializer = serializer