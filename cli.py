import typer
import asyncio
import json
import csv
import sys
from pathlib import Path
from typing import Optional
from typing_extensions import Annotated
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console
from functools import wraps
import dns.resolver
import ipaddress
import logging

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
from utils.logger import setup_logger

app = typer.Typer(help="CataclysmDNS — toolkit avançado de pentest DNS")
console = Console()
logger = setup_logger("cli")


def show_banner():
    """Exibe o banner ASCII art da ferramenta"""
    banner = r"""
 ██████╗ █████╗ ████████╗ █████╗  ██████╗██╗  ██╗   ██╗███████╗███╗   ███╗
██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██║  ╚██╗ ██╔╝██╔════╝████╗ ████║
██║     ███████║   ██║   ███████║██║     ██║   ╚████╔╝ ███████╗██╔████╔██║
██║     ██╔══██║   ██║   ██╔══██║██║     ██║    ╚██╔╝  ╚════██║██║╚██╔╝██║
╚██████╗██║  ██║   ██║   ██║  ██║╚██████╗███████╗██║   ███████║██║ ╚═╝ ██║
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝   ╚══════╝╚═╝     ╚═╝
                  ██████╗ ███╗   ██╗███████╗                              
                  ██╔══██╗████╗  ██║██╔════╝                              
                  ██║  ██║██╔██╗ ██║███████╗                              
                  ██║  ██║██║╚██╗██║╚════██║                              
                  ██████╔╝██║ ╚████║███████║                              
                  ╚═════╝ ╚═╝  ╚═══╝╚══════╝                              
    """
    
    console.print(banner, style="bold cyan")
    console.print("                [yellow]Toolkit avançado de pentest DNS[/]")
    console.print("                [dim white]Versão 1.0 - Por Petronilha[/]\n")


def error_handler(func):
    """Decorator para tratamento de erros global"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            console.print("\n[yellow]Operação cancelada pelo usuário[/]")
            sys.exit(0)
        except FileNotFoundError as e:
            console.print(f"[red]Erro: Arquivo não encontrado: {e}[/]")
            sys.exit(1)
        except Exception as e:
            logger.exception(f"Erro não tratado: {e}")
            console.print(f"[red]Erro: {e}[/]")
            if not isinstance(e, (dns.resolver.NoNameservers, dns.resolver.Timeout)):
                console.print("[yellow]Considere reportar este erro com --debug[/]")
            sys.exit(1)
    return wrapper


def validate_domain(domain: str) -> bool:
    """Valida se o domínio tem formato válido"""
    import re
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def validate_ip(ip: str) -> bool:
    """Valida se é um endereço IP válido"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def save_results(results: dict, output_format: str, output_file: str):
    """Salva os resultados no formato especificado"""
    if output_format.lower() == "json":
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    elif output_format.lower() == "csv":
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['FQDN', 'Type', 'Value'])
            for fqdn, records in results.items():
                for rdtype, values in records.items():
                    for value in values:
                        writer.writerow([fqdn, rdtype, value])
    console.print(f"[green]Resultados salvos em: {output_file}[/]")


@app.command()
@error_handler
def enum(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    wordlist: Annotated[str, typer.Option(help="Wordlist de subdomínios")] = "wordlists/subdomains.txt",
    nameserver: Annotated[Optional[str], typer.Option(help="Servidor DNS customizado (IP)")] = None,
    workers: Annotated[int, typer.Option(help="Número de workers paralelos")] = 20,
    output: Annotated[Optional[str], typer.Option(help="Arquivo de output")] = None,
    format: Annotated[str, typer.Option(help="Formato do output (json, csv)")] = "json",
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Modo verboso")] = False,
):
    """
    Enumeração avançada de subdomínios com múltiplos tipos de registro
    e detecção de wildcard.
    """
    if not validate_domain(domain):
        console.print("[red]Erro: Domínio inválido[/]")
        raise typer.Exit(1)
    
    if nameserver and not validate_ip(nameserver):
        console.print("[red]Erro: Endereço IP inválido para nameserver[/]")
        raise typer.Exit(1)
    
    if not Path(wordlist).exists():
        console.print(f"[red]Erro: Wordlist não encontrada: {wordlist}[/]")
        raise typer.Exit(1)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"[cyan]Enumerando {domain}...", total=None)
        
        subs = [l.strip() for l in open(wordlist, encoding="utf-8") if l.strip()]
        # Removido o limite de permutações
        subs = generate_permutations(subs, limit_permutations=None)
        
        if verbose:
            console.print(f"[dim]Carregados {len(subs)} subdomínios para teste[/]")
        
        types = ["A", "AAAA", "MX", "TXT", "PTR"]
        results = asyncio.run(enum_subdomains(domain, subs, types, nameserver, workers))
        
        progress.update(task, completed=True)
    
    console.print(f"\n[green]Encontrados {len(results)} subdomínios válidos.[/]")
    
    if detect_wildcard(domain):
        console.print("[yellow]⚠️  Atenção: Wildcard DNS detectado.[/]")
    
    if verbose:
        for fqdn, records in results.items():
            console.print(f"\n[bold]{fqdn}[/]")
            for rdtype, values in records.items():
                for value in values:
                    console.print(f"  {rdtype}: {value}")
    
    if output:
        save_results(results, format, output)


@app.command()
@error_handler
def resolve(
    name: Annotated[str, typer.Option(help="FQDN ou IP para resolver")],
    record: Annotated[str, typer.Option(help="Tipo de registro")] = "A",
    nameserver: Annotated[Optional[str], typer.Option(help="Servidor DNS customizado")] = None,
    timeout: Annotated[float, typer.Option(help="Timeout em segundos")] = 2.0,
):
    """Resolve um único registro DNS de forma síncrona."""
    values = resolve_record(name, record, nameserver=nameserver, timeout=timeout)
    if values:
        for v in values:
            console.print(f"[green]{name} {record} -> {v}[/]")
    else:
        console.print(f"[red]❌ Sem resposta para {name} {record}[/]")


@app.command()
@error_handler
def zone_transfer(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    nameserver: Annotated[str, typer.Option(help="Servidor DNS autoritativo")],
    output: Annotated[Optional[str], typer.Option(help="Arquivo de output")] = None,
):
    """Tenta transferência de zona (AXFR)"""
    if not validate_domain(domain):
        console.print("[red]Erro: Domínio inválido[/]")
        raise typer.Exit(1)
    
    if not validate_ip(nameserver) and not validate_domain(nameserver):
        console.print("[red]Erro: Nameserver inválido[/]")
        raise typer.Exit(1)
    
    records = attempt_axfr(domain, nameserver)
    for rdtype, recs in records.items():
        console.print(f"\n[bold]=== {rdtype} ===[/]")
        for r in recs:
            console.print(f" - {r}")
    
    if output and records:
        save_results({"zone_transfer": records}, "json", output)


@app.command()
@error_handler
def brute(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    wordlist: Annotated[str, typer.Option(help="Wordlist para brute force")] = "wordlists/subdomains.txt",
    workers: Annotated[int, typer.Option(help="Workers assíncronos")] = 50,
    output: Annotated[Optional[str], typer.Option(help="Arquivo de output")] = None,
    progress: Annotated[bool, typer.Option(help="Mostrar barra de progresso")] = True,
):
    """Brute force de subdomínios via wordlist"""
    if not validate_domain(domain):
        console.print("[red]Erro: Domínio inválido[/]")
        raise typer.Exit(1)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        disable=not progress,
    ) as progress_bar:
        task = progress_bar.add_task(f"[cyan]Brute force em {domain}...", total=None)
        results = asyncio.run(brute_force(domain, wordlist, workers))
        progress_bar.update(task, completed=True)
    
    console.print(f"\n[green]Brute force: {len(results)} encontrados.[/]")
    
    if output:
        save_results(results, "json", output)


@app.command()
@error_handler
def dnssec(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Modo verboso")] = False,
):
    """Verifica DNSSEC"""
    if not validate_domain(domain):
        console.print("[red]Erro: Domínio inválido[/]")
        raise typer.Exit(1)
    
    enabled = check_dnssec(domain)
    status = '[green]habilitado[/]' if enabled else '[red]não habilitado[/]'
    console.print(f"DNSSEC {status} para {domain}.")


@app.command()
@error_handler
def monitor_dns(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    interval: Annotated[int, typer.Option(help="Intervalo em segundos")] = 300,
    output: Annotated[Optional[str], typer.Option(help="Arquivo de log")] = None,
):
    """Monitora mudanças de registros DNS"""
    if not validate_domain(domain):
        console.print("[red]Erro: Domínio inválido[/]")
        raise typer.Exit(1)
    
    if output:
        # Configurar logger para arquivo
        file_handler = logging.FileHandler(output)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        logging.getLogger("monitoring").addHandler(file_handler)
    
    monitor(domain, interval)


@app.callback()
def main(
    debug: Annotated[bool, typer.Option("--debug", help="Ativar modo debug")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Modo silencioso")] = False,
):
    """CataclysmDNS - Ferramenta avançada de pentest DNS"""
    # Mostra o banner apenas se não estiver no modo silencioso
    if not quiet:
        show_banner()
    
    if debug:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
    if quiet:
        console.quiet = True


if __name__ == "__main__":
    app()