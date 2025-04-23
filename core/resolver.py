import dns.asyncresolver
import dns.resolver
import asyncio
import random
import string
from utils.logger import setup_logger

logger = setup_logger("resolver")


def resolve_record(name: str, rdtype: str, resolver: dns.resolver.Resolver | None = None) -> list[str]:
    """
    Resolve um registro DNS do tipo `rdtype` (A, AAAA, MX, TXT, PTR, etc.)
    e retorna a lista de valores como strings.
    """
    resolver = resolver or dns.resolver.Resolver()
    try:
        answers = resolver.resolve(name, rdtype)
        return [rdata.to_text() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception as e:
        logger.debug(f"Erro ao resolver {name} {rdtype}: {e}")
        return []


async def resolve_subdomain_async(
    sub: str,
    domain: str,
    types: list[str],
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore
) -> dict[str, dict[str, list[str]]]:
    """
    Resolve `sub.domain` para cada tipo em `types` de forma assíncrona.
    Retorna dict {fqdn: {rdtype: [valores]}} apenas para registros encontrados.
    """
    fqdn = f"{sub}.{domain}"
    async with semaphore:
        result: dict[str, list[str]] = {}
        for rd in types:
            try:
                answers = await resolver.resolve(fqdn, rd)
                result[rd] = [rdata.to_text() for rdata in answers]
            except Exception:
                continue

        if result:
            logger.info(f"[+] {fqdn} -> {result}")
            return {fqdn: result}
        return {}


async def enum_subdomains(
    domain: str,
    subs: list[str],
    types: list[str],
    nameserver: str | None = None,
    workers: int = 20
) -> dict[str, dict[str, list[str]]]:
    """
    Enumera `subs` de forma paralela no `domain`, testando todos os `types`.
    Se `nameserver` for informado, usa-o via override.
    """
    if nameserver:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
    else:
        resolver = dns.asyncresolver.get_default_resolver()

    semaphore = asyncio.Semaphore(workers)
    tasks = [
        resolve_subdomain_async(sub, domain, types, resolver, semaphore)
        for sub in subs
    ]
    results = await asyncio.gather(*tasks)
    combined: dict[str, dict[str, list[str]]] = {}
    for r in results:
        combined.update(r)
    return combined


def generate_permutations(
    base: list[str],
    suffixes: list[str] = None,
    prefix_numbers: int = 3
) -> list[str]:
    """
    Cria variações de `base` adicionando:
    - Sufixos comuns (e.g., '-dev', '-test', '-stage')
    - Prefixos numéricos de até `prefix_numbers`
    """
    suffixes = suffixes or ["dev", "test", "stage"]
    perms = set(base)
    for b in base:
        for suf in suffixes:
            perms.add(f"{b}-{suf}")
        for i in range(1, prefix_numbers + 1):
            perms.add(f"{b}{i}")
    return sorted(perms)