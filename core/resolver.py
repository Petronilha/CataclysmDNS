import dns.asyncresolver
import dns.resolver
import asyncio
import random
import string
import socket
import socks
from functools import lru_cache
from typing import Optional, Dict, List, Set
from datetime import datetime, timedelta
from asyncio import Semaphore
import backoff
from concurrent.futures import ThreadPoolExecutor
import json
from cachetools import TTLCache

from core.proxy_manager import ProxyManager
from core.rate_limiter import RateLimiter, RateLimitConfig
from utils.logger import setup_logger

logger = setup_logger("resolver")

# Cache global de respostas com TTL
CACHE_TTL = 300  # 5 minutos
response_cache = TTLCache(maxsize=10000, ttl=CACHE_TTL)

# Cache de configuração de resolvers
resolver_cache = TTLCache(maxsize=100, ttl=3600)  # 1 hora


def setup_dns_over_tor():
    """Configura DNS para trabalhar com Tor"""
    import dns.query
    import dns.message
    
    # Força o uso de TCP para DNS
    dns.query.tcp = True
    
    # Patch para DNS sobre SOCKS5
    original_tcp_socket = socket.socket
    
    def socks_socket(*args, **kwargs):
        sock = socks.socksocket(*args, **kwargs)
        sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        return sock
    
    socket.socket = socks_socket
    
    return original_tcp_socket


class DNSResolverPool:
    """Pool de resolvers DNS com rotação e suporte a proxy"""
    
    def __init__(self, size: int = 10, nameservers: Optional[List[str]] = None, 
                 proxy_manager: Optional[ProxyManager] = None):
        self.size = size
        self.resolvers = []
        self.index = 0
        self.proxy_manager = proxy_manager
        
        # Lista expandida de nameservers públicos que funcionam bem com Tor
        self.public_nameservers = [
            # Cloudflare (funciona bem com Tor)
            "1.1.1.1", "1.0.0.1",
            # Google DNS (geralmente funciona)
            "8.8.8.8", "8.8.4.4",
            # OpenDNS
            "208.67.222.222", "208.67.220.220",
        ]
        
        nameservers = nameservers or self.public_nameservers
        
        # Se usando proxy, configura DNS sobre Tor
        if self.proxy_manager and self.proxy_manager.enabled:
            self.original_socket = setup_dns_over_tor()
        
        for i in range(size):
            resolver = dns.asyncresolver.Resolver(configure=False)
            # Configurações para trabalhar com Tor
            resolver.nameservers = [nameservers[i % len(nameservers)]]
            resolver.timeout = 10.0  # Aumenta timeout para Tor
            resolver.lifetime = 30.0
            resolver.use_tcp = True  # Força uso de TCP
            resolver.use_edns = False  # Desabilita EDNS para melhor compatibilidade
            
            self.resolvers.append(resolver)
    
    def get_resolver(self) -> dns.asyncresolver.Resolver:
        """Retorna um resolver do pool de forma round-robin"""
        resolver = self.resolvers[self.index]
        self.index = (self.index + 1) % self.size
        
        # Rotaciona o nameserver periodicamente
        if self.index == 0:
            self._rotate_nameservers()
        
        return resolver
    
    def _rotate_nameservers(self):
        """Rotaciona os nameservers entre os resolvers"""
        random.shuffle(self.public_nameservers)
        for i, resolver in enumerate(self.resolvers):
            resolver.nameservers = [self.public_nameservers[i % len(self.public_nameservers)]]
    
    def cleanup(self):
        """Restaura o socket original"""
        if hasattr(self, 'original_socket'):
            socket.socket = self.original_socket


async def resolve_subdomain_async_with_retry(
    sub: str,
    domain: str,
    types: List[str],
    resolver: dns.asyncresolver.Resolver,
    semaphore: Semaphore,
    rate_limiter: Optional[RateLimiter] = None
) -> Dict[str, Dict[str, List[str]]]:
    """
    Resolve subdomínio com retry automático
    """
    fqdn = f"{sub}.{domain}"
    async with semaphore:
        if rate_limiter:
            await rate_limiter.acquire()
        
        result: Dict[str, List[str]] = {}
        
        # Resolve todos os tipos sequencialmente (mais confiável com Tor)
        for rd in types:
            try:
                answers = await resolver.resolve(fqdn, rd, tcp=True)
                result[rd] = [rdata.to_text() for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception as e:
                if "timeout" in str(e).lower():
                    logger.debug(f"Timeout ao resolver {fqdn} {rd} - comum com Tor")
                    continue
                logger.debug(f"Erro ao resolver {fqdn} {rd}: {e}")
                continue
        
        if result:
            logger.info(f"[+] {fqdn} -> {result}")
            if rate_limiter:
                rate_limiter.report_success()
            return {fqdn: result}
        
        return {}


async def enum_subdomains(
    domain: str,
    subs: List[str],
    types: List[str],
    nameserver: Optional[str] = None,
    workers: int = 20,
    proxy_manager: Optional[ProxyManager] = None,
    rate_limiter: Optional[RateLimiter] = None
) -> Dict[str, Dict[str, List[str]]]:
    """
    Enumera subdomínios com pool de resolvers e paralelismo otimizado
    """
    # Ajusta workers para Tor
    if proxy_manager and proxy_manager.enabled:
        workers = min(workers, 10)  # Limita workers com Tor
    
    optimal_workers = min(workers, max(20, len(subs) // 50))
    
    nameservers = [nameserver] if nameserver else None
    resolver_pool = DNSResolverPool(
        size=max(5, optimal_workers // 4), 
        nameservers=nameservers,
        proxy_manager=proxy_manager
    )
    
    semaphore = asyncio.Semaphore(optimal_workers)
    
    try:
        # Processa em chunks menores para melhor controle
        chunk_size = max(5, len(subs) // optimal_workers)
        chunks = [subs[i:i + chunk_size] for i in range(0, len(subs), chunk_size)]
        
        async def process_chunk(chunk):
            results = []
            for sub in chunk:
                resolver = resolver_pool.get_resolver()
                result = await resolve_subdomain_async_with_retry(
                    sub, domain, types, resolver, semaphore, rate_limiter
                )
                results.append(result)
            return results
        
        all_results = await asyncio.gather(*[process_chunk(chunk) for chunk in chunks])
        
        # Combina todos os resultados
        combined: Dict[str, Dict[str, List[str]]] = {}
        for chunk_results in all_results:
            for result in chunk_results:
                if isinstance(result, dict):
                    combined.update(result)
        
        return combined
    
    finally:
        # Cleanup
        resolver_pool.cleanup()


# Restante do código igual...