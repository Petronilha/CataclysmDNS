import dns.resolver
import asyncio
from utils.logger import setup_logger

logger = setup_logger("resolver")

async def resolve_subdomain(sub: str, domain: str) -> str | None:
    """
    Tenta resolver sub.domain e retorna o IP, ou None em caso de falha.
    """
    fqdn = f"{sub}.{domain}"
    try:
        answers = dns.resolver.resolve(fqdn, "A")
        ips = [rdata.address for rdata in answers]
        return ",".join(ips)
    except Exception:
        return None

async def enum_subdomains(domain: str, subs: list[str], workers: int = 20) -> dict[str, str]:
    """
    Realiza enumeração paralela de subdomínios.
    """
    results: dict[str, str] = {}
    sem = asyncio.Semaphore(workers)

    async def worker(sub):
        async with sem:
            ip = await resolve_subdomain(sub, domain)
            if ip:
                results[sub] = ip
                logger.info(f"[+] {sub}.{domain} -> {ip}")

    await asyncio.gather(*(worker(s) for s in subs))
    return results

def detect_wildcard(domain: str) -> bool:
    """
    Verifica se há wildcard DNS criando um subdomínio aleatório.
    """
    import random, string
    rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    ip = dns.resolver.resolve(f"{rnd}.{domain}", "A", raise_on_no_answer=False)
    return bool(ip)