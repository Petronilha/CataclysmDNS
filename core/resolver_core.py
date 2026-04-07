import dns.asyncresolver
import dns.resolver
import asyncio

from typing import Optional, Dict, List
from asyncio import Semaphore
from utils.logger import setup_logger
from rich.console import Console

# Importamos o RateLimiter que você já havia criado
from core.rate_limiter import RateLimiter, RateLimitConfig 

logger = setup_logger("resolver_core")

async def resolve_subdomain_async(
    sub: str,
    domain: str,
    types: List[str],
    resolver: dns.asyncresolver.Resolver,
    semaphore: Semaphore,
    rate_limiter: Optional[RateLimiter] = None  # Recebemos o rate_limiter aqui
) -> Dict[str, Dict[str, List[str]]]:
    """
    Resolve subdomínio de forma assíncrona e mostra resultados em tempo real
    """
    fqdn = f"{sub}.{domain}"
    
    async with semaphore:
        # Aplica o Rate Limit ANTES de fazer a requisição DNS
        if rate_limiter:
            await rate_limiter.acquire()
            
        result: Dict[str, List[str]] = {}
        
        for rd in types:
            try:
                answers = await resolver.resolve(fqdn, rd)
                result[rd] = [rdata.to_text() for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception:
                continue
        
        if result:
            return {fqdn: result}
        
        return {}

async def enum_subdomains_core(
    domain: str,
    subs: List[str],
    types: List[str],
    nameserver: Optional[str] = None,
    workers: int = 20,
    console: Console = None,
    timeout: float = 5.0,
    rate_limit: float = 10.0 
) -> Dict[str, Dict[str, List[str]]]:
    """
    Enumera subdomínios com output em tempo real e visual profissional
    """
    resolver = dns.asyncresolver.Resolver(configure=False)
    if nameserver:
        resolver.nameservers = [nameserver]
    else:
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    
    # Aplica o timeout definido pelo usuário!
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2.0 
    
    semaphore = asyncio.Semaphore(workers)
    
    # Configura o Rate Limiter baseado no input do usuário
    rl_config = RateLimitConfig(requests_per_second=rate_limit)
    limiter = RateLimiter(config=rl_config) if rate_limit > 0 else None
    
    tasks = []
    for sub in subs:
        tasks.append(resolve_subdomain_async(
            sub, domain, types, resolver, semaphore, limiter
        ))
    
    combined: Dict[str, Dict[str, List[str]]] = {}
    
    for completed_task in asyncio.as_completed(tasks):
        result = await completed_task
        
        if result:
            for subdominio, records in result.items():
                for rdtype, valores in records.items():
                    for valor in valores:
                        if rdtype in ["A", "AAAA"]:
                            tipo_formatado = f"[bold green][{rdtype}][/]"
                        elif rdtype == "CNAME":
                            tipo_formatado = f"[bold yellow][{rdtype}][/]"
                        elif rdtype == "TXT":
                            tipo_formatado = f"[bold magenta][{rdtype}][/]"
                        else:
                            tipo_formatado = f"[bold cyan][{rdtype}][/]"
                        
                        if console:
                            console.print(f" [bold bright_green][+][/] [white]{subdominio:<35}[/][dim]➔[/] {tipo_formatado:<15} [bright_white]{valor}[/]")
            
            combined.update(result)
    
    return combined