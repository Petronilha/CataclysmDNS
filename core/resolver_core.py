import dns.asyncresolver
import dns.resolver
import asyncio
import random
import string
from typing import Optional, Dict, List, Set
from asyncio import Semaphore
from rich.console import Console
from utils.logger import setup_logger

logger = setup_logger("resolver_core")
console = Console()

async def resolve_subdomain_async(
    sub: str,
    domain: str,
    types: List[str],
    resolver: dns.asyncresolver.Resolver,
    semaphore: Semaphore,
) -> Dict[str, Dict[str, List[str]]]:
    """
    Resolve subdomínio de forma assíncrona e mostra resultados em tempo real
    """
    fqdn = f"{sub}.{domain}"
    async with semaphore:
        result: Dict[str, List[str]] = {}
        
        for rd in types:
            try:
                answers = await resolver.resolve(fqdn, rd)
                result[rd] = [rdata.to_text() for rdata in answers]
                # Mostra resultados imediatamente quando encontrados
                for value in result[rd]:
                    console.print(f"[+] {fqdn} -> {{'{rd}': ['{value}']}}")
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
) -> Dict[str, Dict[str, List[str]]]:
    """
    Enumera subdomínios com output em tempo real
    """
    resolver = dns.asyncresolver.Resolver(configure=False)
    if nameserver:
        resolver.nameservers = [nameserver]
    else:
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    
    resolver.timeout = 2.0
    resolver.lifetime = 5.0
    
    semaphore = asyncio.Semaphore(workers)
    
    tasks = []
    for sub in subs:
        tasks.append(resolve_subdomain_async(sub, domain, types, resolver, semaphore))
    
    results = await asyncio.gather(*tasks)
    
    combined: Dict[str, Dict[str, List[str]]] = {}
    for result in results:
        if result:
            combined.update(result)
    
    return combined