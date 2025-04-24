from dataclasses import dataclass
from typing import Dict, Optional
from .cache_types import CacheType, CacheConfig
from .cache_manager import CacheManager

@dataclass
class DNSCacheConfig:
    """Configurações específicas para diferentes tipos de cache DNS"""
    # Cache para resultados de resolução DNS
    resolution_cache: CacheConfig = CacheConfig(
        cache_type=CacheType.MEMORY,
        ttl=300,  # 5 minutos
        max_size=10000
    )
    
    # Cache para resultados de enumeração de subdomínios
    enumeration_cache: CacheConfig = CacheConfig(
        cache_type=CacheType.DISK,
        ttl=3600,  # 1 hora
        disk_path="cache_data/enumeration",
        serializer="json"
    )
    
    # Cache para resultados de reconhecimento passivo
    passive_recon_cache: CacheConfig = CacheConfig(
        cache_type=CacheType.SQLITE,
        ttl=86400,  # 24 horas
        sqlite_path="cache_data/passive.db"
    )
    
    # Cache para resultados de takeover
    takeover_cache: CacheConfig = CacheConfig(
        cache_type=CacheType.MEMORY,
        ttl=1800,  # 30 minutos
        max_size=5000
    )
    
    # Cache para resultados de DNSSEC
    dnssec_cache: CacheConfig = CacheConfig(
        cache_type=CacheType.MEMORY,
        ttl=3600,  # 1 hora
        max_size=1000
    )
    
    # Cache para API responses (VirusTotal, etc)
    api_cache: CacheConfig = CacheConfig(
        cache_type=CacheType.DISK,
        ttl=7200,  # 2 horas
        disk_path="cache_data/api",
        serializer="json"
    )


class CachingSystem:
    """Sistema centralizado de cache para o CataclysmDNS"""
    
    def __init__(self, config: Optional[DNSCacheConfig] = None):
        self.config = config or DNSCacheConfig()
        
        # Inicializa os diferentes cache managers
        self.resolution_cache = CacheManager(self.config.resolution_cache)
        self.enumeration_cache = CacheManager(self.config.enumeration_cache)
        self.passive_cache = CacheManager(self.config.passive_recon_cache)
        self.takeover_cache = CacheManager(self.config.takeover_cache)
        self.dnssec_cache = CacheManager(self.config.dnssec_cache)
        self.api_cache = CacheManager(self.config.api_cache)
        
        # Mapa de cache por tipo
        self.cache_map = {
            "resolution": self.resolution_cache,
            "enumeration": self.enumeration_cache,
            "passive": self.passive_cache,
            "takeover": self.takeover_cache,
            "dnssec": self.dnssec_cache,
            "api": self.api_cache
        }
    
    def get_cache(self, cache_type: str) -> CacheManager:
        """Retorna o cache manager para um tipo específico"""
        return self.cache_map.get(cache_type, self.resolution_cache)
    
    async def clear_all(self):
        """Limpa todos os caches"""
        for cache in self.cache_map.values():
            await cache.clear()
    
    def get_all_stats(self) -> Dict:
        """Retorna estatísticas de todos os caches"""
        stats = {}
        for name, cache in self.cache_map.items():
            stats[name] = cache.get_stats()
        return stats
    
    def reset_all_stats(self):
        """Reseta estatísticas de todos os caches"""
        for cache in self.cache_map.values():
            cache.reset_stats()


# Instância global do sistema de cache
caching_system = CachingSystem()


# Funções de conveniência para acessar caches específicos
def get_resolution_cache() -> CacheManager:
    return caching_system.get_cache("resolution")

def get_enumeration_cache() -> CacheManager:
    return caching_system.get_cache("enumeration")

def get_passive_cache() -> CacheManager:
    return caching_system.get_cache("passive")

def get_takeover_cache() -> CacheManager:
    return caching_system.get_cache("takeover")

def get_dnssec_cache() -> CacheManager:
    return caching_system.get_cache("dnssec")

def get_api_cache() -> CacheManager:
    return caching_system.get_cache("api")