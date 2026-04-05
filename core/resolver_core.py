import dns.asyncresolver
import dns.resolver
import asyncio

from typing import Optional, Dict, List
from asyncio import Semaphore
from utils.logger import setup_logger
from rich import print as rprint
from rich.console import Console

logger = setup_logger("resolver_core")

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
    console: Console = None
) -> Dict[str, Dict[str, List[str]]]:
    """
    Enumera subdomínios com output em tempo real e visual profissional
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
        # Assumindo que resolve_subdomain_async está definida em outro lugar neste arquivo
        tasks.append(resolve_subdomain_async(sub, domain, types, resolver, semaphore))
    
    combined: Dict[str, Dict[str, List[str]]] = {}
    
    # Usamos as_completed em vez de gather para ter o "Live Preview" real!
    for completed_task in asyncio.as_completed(tasks):
        result = await completed_task
        
        if result:
            # result tem o formato: {"sub.dominio.com": {"A": ["1.2.3.4"]}}
            for subdominio, records in result.items():
                for rdtype, valores in records.items():
                    for valor in valores:
                        
                        # --- INÍCIO DA ESTILIZAÇÃO DO LIVE PREVIEW ---
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