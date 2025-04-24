import asyncio
from rich.console import Console
from utils.wordlist_loader import load_wordlist
from core.resolver_core import enum_subdomains_core
from utils.logger import setup_logger

logger = setup_logger("brute_force")
console = Console()

async def brute_force(domain: str, wordlist_file: str, workers: int = 50):
    """
    Brute force subdomains using a wordlist com output em tempo real
    """
    console.print(f"[cyan]Iniciando brute force em {domain}...[/cyan]")
    console.print()  # Linha em branco
    
    subs = load_wordlist(wordlist_file)
    types = ["A", "AAAA"]
    
    # Usa o resolver_core que já mostra resultados em tempo real
    results = await enum_subdomains_core(
        domain=domain, 
        subs=subs, 
        types=types, 
        workers=workers
    )
    
    return results