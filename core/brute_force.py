import asyncio
from utils.wordlist_loader import load_wordlist
from core.resolver import enum_subdomains
from utils.logger import setup_logger

logger = setup_logger("brute_force")

async def brute_force(domain: str, wordlist_file: str, workers: int = 50):
    """Brute force subdomains using a wordlist."""
    subs = load_wordlist(wordlist_file)
    # Default DNS record types to query during brute force
    types = ["A", "AAAA"]
    results = await enum_subdomains(domain=domain, subs=subs, types=types, workers=workers)
    return results

async def resolve_subs(subs: list[str], domain: str, workers: int):
    from core.resolver import enum_subdomains
    return await enum_subdomains(domain, subs, workers)