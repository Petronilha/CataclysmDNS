import dns.asyncresolver
import dns.resolver
import asyncio
import random
import string
from functools import lru_cache
from typing import Optional, Dict, List, Set
from datetime import datetime, timedelta
from asyncio import Semaphore
import backoff
from concurrent.futures import ThreadPoolExecutor

from utils.logger import setup_logger

logger = setup_logger("resolver")

# Cache global de respostas
CACHE_TTL = 300  # 5 minutos
response_cache: Dict[str, Dict] = {}


class DNSResolverPool:
    """Pool de resolvers DNS para melhor performance"""
    
    def __init__(self, size: int = 10, nameservers: Optional[List[str]] = None):
        self.size = size
        self.resolvers = []
        
        for _ in range(size):
            if nameservers:
                resolver = dns.asyncresolver.Resolver(configure=False)
                resolver.nameservers = nameservers
            else:
                resolver = dns.asyncresolver.get_default_resolver()
            
            resolver.timeout = 2.0
            resolver.lifetime = 5.0
            self.resolvers.append(resolver)
    
    def get_resolver(self) -> dns.asyncresolver.Resolver:
        """Retorna um resolver do pool de forma circular"""
        resolver = self.resolvers.pop(0)
        self.resolvers.append(resolver)
        return resolver


def cache_response(func):
    """Decorator para cache de respostas DNS"""
    def wrapper(*args, **kwargs):
        cache_key = f"{args[0]}:{args[1]}"  # name:rdtype
        now = datetime.now()
        
        if cache_key in response_cache:
            cached_data = response_cache[cache_key]
            if now - cached_data['timestamp'] < timedelta(seconds=CACHE_TTL):
                logger.debug(f"Cache hit: {cache_key}")
                return cached_data['response']
        
        response = func(*args, **kwargs)
        response_cache[cache_key] = {'response': response, 'timestamp': now}
        return response
    
    return wrapper


@cache_response
def resolve_record(
    name: str,
    rdtype: str,
    nameserver: Optional[str] = None,
    timeout: float = 2.0
) -> List[str]:
    """
    Resolve um registro DNS com cache
    """
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    
    try:
        answers = resolver.resolve(name, rdtype)
        return [rdata.to_text() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception as e:
        logger.debug(f"Erro ao resolver {name} {rdtype}: {e}")
        return []


@backoff.on_exception(
    backoff.expo,
    (dns.resolver.Timeout, dns.resolver.NoNameservers),
    max_tries=3,
    max_time=10
)
async def resolve_subdomain_async_with_retry(
    sub: str,
    domain: str,
    types: List[str],
    resolver: dns.asyncresolver.Resolver,
    semaphore: Semaphore
) -> Dict[str, Dict[str, List[str]]]:
    """
    Resolve subdomínio com retry automático
    """
    fqdn = f"{sub}.{domain}"
    async with semaphore:
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
            return {fqdn: result}
        return {}


async def enum_subdomains(
    domain: str,
    subs: List[str],
    types: List[str],
    nameserver: Optional[str] = None,
    workers: int = 20
) -> Dict[str, Dict[str, List[str]]]:
    """
    Enumera subdomínios com pool de resolvers
    """
    nameservers = [nameserver] if nameserver else None
    resolver_pool = DNSResolverPool(size=max(5, workers // 4), nameservers=nameservers)
    
    semaphore = asyncio.Semaphore(workers)
    
    tasks = []
    for sub in subs:
        resolver = resolver_pool.get_resolver()
        task = resolve_subdomain_async_with_retry(sub, domain, types, resolver, semaphore)
        tasks.append(task)
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    combined: Dict[str, Dict[str, List[str]]] = {}
    for r in results:
        if isinstance(r, dict):
            combined.update(r)
        elif isinstance(r, Exception):
            logger.warning(f"Erro durante enumeração: {r}")
    
    return combined


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