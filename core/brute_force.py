import asyncio
from utils.wordlist_loader import load_wordlist
from core.resolver import resolve_subdomain
from utils.logger import setup_logger

logger = setup_logger("brute_force")

async def brute_force(domain: str, wordlist_file: str, workers: int = 50):
    subs = load_wordlist(wordlist_file)
    return await asyncio.create_task(resolve_subs(subs:=subs, domain=domain, workers=workers))

async def resolve_subs(subs: list[str], domain: str, workers: int):
    from core.resolver import enum_subdomains
    return await enum_subdomains(domain, subs, workers)