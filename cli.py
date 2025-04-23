import typer
import asyncio

from core.resolver import (
    enum_subdomains,
    generate_permutations,
    resolve_record,
    detect_wildcard,
)
from core.zone_transfer import attempt_axfr
from core.brute_force import brute_force
from core.dnssec_checker import check_dnssec
from core.monitoring import monitor

app = typer.Typer(help="CataclysmDNS — toolkit avançado de pentest DNS")

@app.command()
def enum(
    domain: str = typer.Option(..., help="Domínio alvo"),
    wordlist: str = typer.Option("wordlists/subdomains.txt", help="Wordlist de subdomínios"),
    nameserver: str = typer.Option(None, help="Servidor DNS customizado (IP)"),
    workers: int = typer.Option(20, help="Número de workers paralelos"),
):
    """
    Enumeração avançada de subdomínios com múltiplos tipos de registro
    e detecção de wildcard.
    """
    subs = [l.strip() for l in open(wordlist, encoding="utf-8") if l.strip()]
    subs = generate_permutations(subs)
    types = ["A", "AAAA", "MX", "TXT", "PTR"]
    results = asyncio.run(enum_subdomains(domain, subs, types, nameserver, workers))

    typer.echo(f"\nEncontrados {len(results)} subdomínios válidos.")
    if detect_wildcard(domain):
        typer.echo("[!] Atenção: Wildcard DNS detectado.")

@app.command()
def resolve(
    name: str = typer.Option(..., help="FQDN ou IP para resolver"),
    record: str = typer.Option("A", help="Tipo de registro (A, AAAA, MX, TXT, PTR)"),
):
    """
    Resolve um único registro DNS de forma síncrona.
    """
    values = resolve_record(name, record)
    if values:
        for v in values:
            typer.echo(f"{name} {record} -> {v}")
    else:
        typer.echo(f"❌ Sem resposta para {name} {record}")

@app.command()
def zone_transfer(
    domain: str = typer.Option(..., help="Domínio alvo"),
    nameserver: str = typer.Option(..., help="Servidor DNS autoritativo"),
):
    """Tenta transferência de zona (AXFR)"""
    records = attempt_axfr(domain, nameserver)
    for rdtype, recs in records.items():
        typer.echo(f"\n=== {rdtype} ===")
        for r in recs:
            typer.echo(f" - {r}")

@app.command()
def brute(
    domain: str = typer.Option(..., help="Domínio alvo"),
    wordlist: str = typer.Option("wordlists/subdomains.txt", help="Wordlist para brute force"),
    workers: int = typer.Option(50, help="Workers assíncronos"),
):
    """Brute force de subdomínios via wordlist"""
    results = asyncio.run(brute_force(domain, wordlist, workers))
    typer.echo(f"\nBrute force: {len(results)} encontrados.")

@app.command()
def dnssec(
    domain: str = typer.Option(..., help="Domínio alvo"),
):
    """Verifica DNSSEC"""
    enabled = check_dnssec(domain)
    typer.echo(f"DNSSEC {'habilitado' if enabled else 'não habilitado'} para {domain}.")

@app.command()
def monitor_dns(
    domain: str = typer.Option(..., help="Domínio alvo"),
    interval: int = typer.Option(300, help="Intervalo em segundos"),
):
    """Monitora mudanças de registros DNS"""
    monitor(domain, interval)

if __name__ == "__main__":
    app()