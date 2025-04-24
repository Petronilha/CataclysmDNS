# core/cache_types.py
from enum import Enum
from dataclasses import dataclass
from typing import Optional

class CacheType(Enum):
    MEMORY = "memory"
    DISK = "disk"
    REDIS = "redis"
    SQLITE = "sqlite"


@dataclass
class CacheConfig:
    cache_type: CacheType = CacheType.MEMORY
    ttl: int = 3600  # 1 hora
    max_size: int = 10000
    redis_url: Optional[str] = None
    sqlite_path: Optional[str] = "cache.db"
    disk_path: Optional[str] = "cache_data"
    compression: bool = True
    serializer: str = "json"  # json ou pickle