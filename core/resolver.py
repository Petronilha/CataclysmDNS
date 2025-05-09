import dns.asyncresolver
import dns.resolver
import asyncio
import random
import string
from typing import Optional, Dict, List, Set
from asyncio import Semaphore
from cachetools import TTLCache

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger

logger = setup_logger("resolver")

# Cache global de respostas com TTL
CACHE_TTL = 300  # 5 minutos
response_cache = TTLCache(maxsize=10000, ttl=CACHE_TTL)


class DNSResolverPool:
    """Pool de resolvers DNS com rotação"""
    
    def __init__(self, size: int = 10, nameservers: Optional[List[str]] = None):
        self.size = size
        self.resolvers = []
        self.index = 0
        
        # Lista de nameservers públicos
        self.public_nameservers = [
            "1.1.1.1", "1.0.0.1",  # Cloudflare
            "8.8.8.8", "8.8.4.4",  # Google DNS
            "208.67.222.222", "208.67.220.220",  # OpenDNS
        ]
        
        nameservers = nameservers or self.public_nameservers
        
        for i in range(size):
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers = [nameservers[i % len(nameservers)]]
            resolver.timeout = 5.0
            resolver.lifetime = 10.0
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
        
        for rd in types:
            try:
                answers = await resolver.resolve(fqdn, rd)
                result[rd] = [rdata.to_text() for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception as e:
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
    rate_limiter: Optional[RateLimiter] = None
) -> Dict[str, Dict[str, List[str]]]:
    """
    Enumera subdomínios com pool de resolvers e paralelismo otimizado
    """
    optimal_workers = min(workers, max(20, len(subs) // 50))
    
    nameservers = [nameserver] if nameserver else None
    resolver_pool = DNSResolverPool(
        size=max(5, optimal_workers // 4), 
        nameservers=nameservers
    )
    
    semaphore = asyncio.Semaphore(optimal_workers)
    
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


def resolve_record(
    name: str,
    rdtype: str,
    nameserver: Optional[str] = None,
    timeout: float = 2.0
) -> List[str]:
    """
    Versão síncrona para compatibilidade
    """
    cache_key = f"{name}:{rdtype}"
    
    if cache_key in response_cache:
        logger.debug(f"Cache hit: {cache_key}")
        return response_cache[cache_key]
    
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    
    try:
        answers = resolver.resolve(name, rdtype)
        result = [rdata.to_text() for rdata in answers]
        response_cache[cache_key] = result
        return result
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception as e:
        logger.debug(f"Erro ao resolver {name} {rdtype}: {e}")
        return []


def generate_permutations(
    base: List[str],
    suffixes: Optional[List[str]] = None,
    prefixes: Optional[List[str]] = None,
    prefix_numbers: int = 3,
    limit_permutations: Optional[int] = None
) -> List[str]:
    """
    Geração de permutações com opção de limite
    """
    suffixes = suffixes or ["dev", "test", "stage", "prod", "api", "admin"]
    prefixes = prefixes or ["vpn", "mail", "www", "app", "cloud"]
    
    perms = set(base)
    
    # Adiciona sufixos
    for b in base:
        for suf in suffixes:
            perms.add(f"{b}-{suf}")
            perms.add(f"{b}{suf}")
    
    # Adiciona prefixos
    for b in base:
        for pre in prefixes:
            perms.add(f"{pre}-{b}")
            perms.add(f"{pre}{b}")
    
    # Adiciona números
    for b in base:
        for i in range(1, prefix_numbers + 1):
            perms.add(f"{b}{i}")
            perms.add(f"{b}-{i}")
    
    # Aplica limite se especificado
    if limit_permutations and len(perms) > limit_permutations:
        logger.warning(f"Limitando permutações de {len(perms)} para {limit_permutations}")
        perms = set(list(perms)[:limit_permutations])
    else:
        logger.info(f"Processando {len(perms)} permutações")
    
    return sorted(perms)


def detect_wildcard(domain: str, tests: int = 5) -> bool:
    """
    Detecção de wildcard DNS aprimorada com múltiplos testes
    """
    random_subs = []
    for _ in range(tests):
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        random_subs.append(rnd)
    
    positive_responses = 0
    
    for sub in random_subs:
        try:
            answers = dns.resolver.resolve(f"{sub}.{domain}", "A", raise_on_no_answer=False)
            if answers:
                positive_responses += 1
        except Exception:
            continue
    
    # Se mais de 60% dos testes aleatorios responderem, provavelmente é wildcard
    wildcard_detected = positive_responses >= (tests * 0.6)
    
    if wildcard_detected:
        logger.warning(f"Wildcard DNS detectado para {domain}")
    
    return wildcard_detected