from typing import Any, Optional, Dict, Union
from datetime import datetime, timedelta
import json
import pickle
import sqlite3
from pathlib import Path
from cachetools import TTLCache, LRUCache
from dataclasses import dataclass
from enum import Enum
import aiofiles
from functools import wraps

from utils.enhanced_logger import setup_enhanced_logger

logger = setup_enhanced_logger("cache_manager")


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


class CacheStats:
    """Estatísticas do cache"""
    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.deletes = 0
        self.last_reset = datetime.now()
    
    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
    
    def reset(self):
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.deletes = 0
        self.last_reset = datetime.now()


class BaseCacheBackend:
    """Interface base para backends de cache"""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.stats = CacheStats()
    
    async def get(self, key: str) -> Optional[Any]:
        raise NotImplementedError
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        raise NotImplementedError
    
    async def delete(self, key: str) -> bool:
        raise NotImplementedError
    
    async def clear(self) -> bool:
        raise NotImplementedError
    
    async def exists(self, key: str) -> bool:
        raise NotImplementedError


class MemoryCacheBackend(BaseCacheBackend):
    """Backend de cache em memória usando cachetools"""
    
    def __init__(self, config: CacheConfig):
        super().__init__(config)
        self.cache = TTLCache(maxsize=config.max_size, ttl=config.ttl)
    
    async def get(self, key: str) -> Optional[Any]:
        value = self.cache.get(key)
        if value is not None:
            self.stats.hits += 1
        else:
            self.stats.misses += 1
        return value
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        try:
            if ttl:
                # Criar um cache temporário para este item específico
                temp_cache = TTLCache(maxsize=1, ttl=ttl)
                temp_cache[key] = value
                self.cache[key] = temp_cache[key]
            else:
                self.cache[key] = value
            self.stats.sets += 1
            return True
        except Exception as e:
            logger.error(f"Erro ao definir cache: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        try:
            if key in self.cache:
                del self.cache[key]
                self.stats.deletes += 1
                return True
            return False
        except Exception as e:
            logger.error(f"Erro ao deletar cache: {e}")
            return False
    
    async def clear(self) -> bool:
        self.cache.clear()
        return True
    
    async def exists(self, key: str) -> bool:
        return key in self.cache


class DiskCacheBackend(BaseCacheBackend):
    """Backend de cache em disco"""
    
    def __init__(self, config: CacheConfig):
        super().__init__(config)
        self.cache_dir = Path(config.disk_path)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.cache_dir / "metadata.json"
        self.metadata = self._load_metadata()
    
    def _load_metadata(self) -> Dict:
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
    
    def _save_metadata(self):
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f)
    
    def _get_file_path(self, key: str) -> Path:
        # Hash simples para evitar problemas com nomes de arquivo
        safe_key = str(hash(key))
        return self.cache_dir / f"{safe_key}.cache"
    
    async def get(self, key: str) -> Optional[Any]:
        file_path = self._get_file_path(key)
        
        if not file_path.exists():
            self.stats.misses += 1
            return None
        
        # Verificar TTL
        if key in self.metadata:
            expiry = self.metadata[key].get("expiry")
            if expiry and datetime.fromisoformat(expiry) < datetime.now():
                await self.delete(key)
                self.stats.misses += 1
                return None
        
        try:
            async with aiofiles.open(file_path, 'rb') as f:
                data = await f.read()
            
            if self.config.serializer == "json":
                value = json.loads(data.decode())
            else:
                value = pickle.loads(data)
            
            self.stats.hits += 1
            return value
        except Exception as e:
            logger.error(f"Erro ao ler cache do disco: {e}")
            self.stats.misses += 1
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        file_path = self._get_file_path(key)
        
        try:
            if self.config.serializer == "json":
                data = json.dumps(value).encode()
            else:
                data = pickle.dumps(value)
            
            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(data)
            
            # Atualizar metadata
            expiry = None
            if ttl:
                expiry = (datetime.now() + timedelta(seconds=ttl)).isoformat()
            elif self.config.ttl:
                expiry = (datetime.now() + timedelta(seconds=self.config.ttl)).isoformat()
            
            self.metadata[key] = {
                "created": datetime.now().isoformat(),
                "expiry": expiry
            }
            self._save_metadata()
            
            self.stats.sets += 1
            return True
        except Exception as e:
            logger.error(f"Erro ao salvar cache no disco: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        file_path = self._get_file_path(key)
        
        try:
            if file_path.exists():
                file_path.unlink()
            
            if key in self.metadata:
                del self.metadata[key]
                self._save_metadata()
            
            self.stats.deletes += 1
            return True
        except Exception as e:
            logger.error(f"Erro ao deletar cache do disco: {e}")
            return False
    
    async def clear(self) -> bool:
        try:
            for file in self.cache_dir.glob("*.cache"):
                file.unlink()
            self.metadata.clear()
            self._save_metadata()
            return True
        except Exception as e:
            logger.error(f"Erro ao limpar cache do disco: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        file_path = self._get_file_path(key)
        return file_path.exists()


class RedisCacheBackend(BaseCacheBackend):
    """Backend de cache Redis"""
    
    def __init__(self, config: CacheConfig):
        super().__init__(config)
        self.redis_url = config.redis_url or "redis://localhost:6379/0"
        self.redis = None
        self._connect()
    
    def _connect(self):
        try:
            import aioredis
            self.redis = aioredis.from_url(self.redis_url)
        except ImportError:
            logger.error("aioredis não está instalado. Use pip install aioredis")
        except Exception as e:
            logger.error(f"Erro ao conectar ao Redis: {e}")
    
    async def get(self, key: str) -> Optional[Any]:
        if not self.redis:
            return None
        
        try:
            data = await self.redis.get(key)
            if data is None:
                self.stats.misses += 1
                return None
            
            if self.config.serializer == "json":
                value = json.loads(data.decode())
            else:
                value = pickle.loads(data)
            
            self.stats.hits += 1
            return value
        except Exception as e:
            logger.error(f"Erro ao obter do Redis: {e}")
            self.stats.misses += 1
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        if not self.redis:
            return False
        
        try:
            if self.config.serializer == "json":
                data = json.dumps(value).encode()
            else:
                data = pickle.dumps(value)
            
            expire = ttl or self.config.ttl
            if expire:
                await self.redis.setex(key, expire, data)
            else:
                await self.redis.set(key, data)
            
            self.stats.sets += 1
            return True
        except Exception as e:
            logger.error(f"Erro ao definir no Redis: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        if not self.redis:
            return False
        
        try:
            result = await self.redis.delete(key)
            if result:
                self.stats.deletes += 1
            return bool(result)
        except Exception as e:
            logger.error(f"Erro ao deletar do Redis: {e}")
            return False
    
    async def clear(self) -> bool:
        if not self.redis:
            return False
        
        try:
            await self.redis.flushdb()
            return True
        except Exception as e:
            logger.error(f"Erro ao limpar Redis: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        if not self.redis:
            return False
        
        try:
            return await self.redis.exists(key) > 0
        except Exception as e:
            logger.error(f"Erro ao verificar existência no Redis: {e}")
            return False


class SQLiteCacheBackend(BaseCacheBackend):
    """Backend de cache SQLite"""
    
    def __init__(self, config: CacheConfig):
        super().__init__(config)
        self.db_path = config.sqlite_path or "cache.db"
        self._init_db()
    
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value BLOB,
                    expiry TIMESTAMP,
                    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_expiry ON cache(expiry)")
            conn.commit()
    
    async def get(self, key: str) -> Optional[Any]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT value, expiry FROM cache WHERE key = ?",
                (key,)
            )
            row = cursor.fetchone()
            
            if not row:
                self.stats.misses += 1
                return None
            
            value_data, expiry = row
            
            # Verificar expiração
            if expiry and datetime.fromisoformat(expiry) < datetime.now():
                await self.delete(key)
                self.stats.misses += 1
                return None
            
            try:
                if self.config.serializer == "json":
                    value = json.loads(value_data.decode())
                else:
                    value = pickle.loads(value_data)
                
                self.stats.hits += 1
                return value
            except Exception as e:
                logger.error(f"Erro ao deserializar do SQLite: {e}")
                self.stats.misses += 1
                return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        try:
            if self.config.serializer == "json":
                value_data = json.dumps(value).encode()
            else:
                value_data = pickle.dumps(value)
            
            expiry = None
            if ttl:
                expiry = (datetime.now() + timedelta(seconds=ttl)).isoformat()
            elif self.config.ttl:
                expiry = (datetime.now() + timedelta(seconds=self.config.ttl)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cache (key, value, expiry)
                    VALUES (?, ?, ?)
                    """,
                    (key, value_data, expiry)
                )
                conn.commit()
            
            self.stats.sets += 1
            return True
        except Exception as e:
            logger.error(f"Erro ao salvar no SQLite: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                conn.commit()
                
                if cursor.rowcount > 0:
                    self.stats.deletes += 1
                    return True
                return False
        except Exception as e:
            logger.error(f"Erro ao deletar do SQLite: {e}")
            return False
    
    async def clear(self) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM cache")
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Erro ao limpar SQLite: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT 1 FROM cache WHERE key = ? AND (expiry IS NULL OR expiry > ?)",
                (key, datetime.now().isoformat())
            )
            return cursor.fetchone() is not None


class CacheManager:
    """Gerenciador principal de cache com suporte a múltiplos backends"""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.backend = self._create_backend()
        self.namespace_separator = ":"
    
    def _create_backend(self) -> BaseCacheBackend:
        if self.config.cache_type == CacheType.MEMORY:
            return MemoryCacheBackend(self.config)
        elif self.config.cache_type == CacheType.DISK:
            return DiskCacheBackend(self.config)
        elif self.config.cache_type == CacheType.REDIS:
            return RedisCacheBackend(self.config)
        elif self.config.cache_type == CacheType.SQLITE:
            return SQLiteCacheBackend(self.config)
        else:
            raise ValueError(f"Tipo de cache não suportado: {self.config.cache_type}")
    
    def _make_key(self, namespace: str, key: str) -> str:
        """Cria uma chave com namespace"""
        return f"{namespace}{self.namespace_separator}{key}"
    
    async def get(self, key: str, namespace: str = "default") -> Optional[Any]:
        """Obtém um valor do cache"""
        full_key = self._make_key(namespace, key)
        return await self.backend.get(full_key)
    
    async def set(self, key: str, value: Any, namespace: str = "default", ttl: Optional[int] = None) -> bool:
        """Define um valor no cache"""
        full_key = self._make_key(namespace, key)
        return await self.backend.set(full_key, value, ttl)
    
    async def delete(self, key: str, namespace: str = "default") -> bool:
        """Remove um valor do cache"""
        full_key = self._make_key(namespace, key)
        return await self.backend.delete(full_key)
    
    async def clear(self, namespace: Optional[str] = None) -> bool:
        """Limpa o cache (todo ou por namespace)"""
        if namespace is None:
            return await self.backend.clear()
        else:
            # Limpar apenas um namespace específico
            # Isso requer implementação específica por backend
            logger.warning(f"Limpeza por namespace não implementada para {self.config.cache_type}")
            return False
    
    async def exists(self, key: str, namespace: str = "default") -> bool:
        """Verifica se uma chave existe no cache"""
        full_key = self._make_key(namespace, key)
        return await self.backend.exists(full_key)
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas do cache"""
        return {
            "hits": self.backend.stats.hits,
            "misses": self.backend.stats.misses,
            "sets": self.backend.stats.sets,
            "deletes": self.backend.stats.deletes,
            "hit_rate": self.backend.stats.hit_rate,
            "last_reset": self.backend.stats.last_reset.isoformat()
        }
    
    def reset_stats(self):
        """Reseta as estatísticas do cache"""
        self.backend.stats.reset()


# Decorador de cache para funções assíncronas
def cached(namespace: str = "default", ttl: Optional[int] = None, key_func: Optional[callable] = None):
    """
    Decorador para cachear resultados de funções assíncronas
    
    Args:
        namespace: Namespace do cache
        ttl: Tempo de vida em segundos
        key_func: Função para gerar a chave de cache baseada nos argumentos
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Obter o cache manager do contexto
            cache_manager = getattr(wrapper, '_cache_manager', None)
            if not cache_manager:
                return await func(*args, **kwargs)
            
            # Gerar chave de cache
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Chave padrão baseada no nome da função e argumentos
                cache_key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            
            # Tentar obter do cache
            cached_value = await cache_manager.get(cache_key, namespace)
            if cached_value is not None:
                logger.debug(f"Cache hit para {cache_key}")
                return cached_value
            
            # Cache miss - executar função
            result = await func(*args, **kwargs)
            
            # Armazenar no cache
            await cache_manager.set(cache_key, result, namespace, ttl)
            
            return result
        
        return wrapper
    return decorator