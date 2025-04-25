import typer
import asyncio
import json
import csv
import sys
from pathlib import Path
from typing import Optional, Dict, List
from typing_extensions import Annotated
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from functools import wraps
import dns.resolver
import ipaddress
import logging

# Imports melhorados
from core.exceptions import (
    CataclysmDNSError,
    DNSTimeoutError,
    DNSResolutionError,
    NetworkError,
    WordlistError,
    InvalidConfigurationError,
    ZoneTransferError,
    PassiveReconError,
    TakeoverDetectionError
)
from core.resolver_enhanced import EnhancedDNSResolver, create_enhanced_resolver
from core.resolver_core import enum_subdomains_core
from utils.enhanced_logger import setup_enhanced_logger, OperationLogger
from utils.retry_handler import retry_with_backoff, DNS_RETRY_CONFIG
from utils.log_cleaner import setup_log_cleaning

# Imports originais mantidos para compatibilidade
from core.resolver import (
    generate_permutations,
    detect_wildcard,
)
from core.zone_transfer import attempt_axfr
from core.brute_force import brute_force
from core.dnssec_checker import check_dnssec
from core.monitoring import monitor
from core.rate_limiter import RateLimiter, RateLimitConfig
from core.takeover_detector import SubdomainTakeoverDetector
from utils.wordlist_loader import load_wordlist
from core.passive_recon import PassiveRecon
# Temporariamente removido para evitar erros de importação
# from core.cache_config import caching_system

app = typer.Typer(help="CataclysmDNS — toolkit avançado de pentest DNS")
console = Console(force_terminal=True)  # Para garantir saída imediata

# Logger aprimorado
logger = setup_enhanced_logger(
    "cli",
    json_file="logs/cli_operations.log" if "--debug" in sys.argv else None,
    verbose="--verbose" in sys.argv or "-v" in sys.argv,
    console_output="--debug" in sys.argv  # Só mostra no console se estiver em modo debug
)


def handle_specific_errors(func):
    """Decorator para tratamento específico de erros na CLI"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except DNSTimeoutError as e:
            logger.error(f"Timeout ao resolver {e.domain}: aguardou {e.timeout}s", 
                        extra={"extra_data": {"error_type": "timeout", "domain": e.domain}})
            console.print(f"[red]Erro: Timeout na resolução DNS para {e.domain}[/]")
            raise typer.Exit(1)
        except DNSResolutionError as e:
            logger.error(f"Erro de resolução DNS: {e.message}", 
                        extra={"extra_data": {"error_type": "resolution"}})
            console.print(f"[red]Erro: Falha na resolução DNS - {e.message}[/]")
            raise typer.Exit(1)
        except WordlistError as e:
            logger.error(f"Erro com wordlist: {e.message}", 
                        extra={"extra_data": {"error_type": "wordlist"}})
            console.print(f"[red]Erro: Problema com a wordlist - {e.message}[/]")
            raise typer.Exit(1)
        except NetworkError as e:
            logger.error(f"Erro de rede: {e.message}", 
                        extra={"extra_data": {"error_type": "network"}})
            console.print(f"[red]Erro: Problema de conectividade - {e.message}[/]")
            console.print("[yellow]Sugestão: Verifique sua conexão ou tente novamente mais tarde[/]")
            raise typer.Exit(1)
        except InvalidConfigurationError as e:
            logger.error(f"Configuração inválida: {e.message}", 
                        extra={"extra_data": {"error_type": "config"}})
            console.print(f"[red]Erro: Configuração inválida - {e.message}[/]")
            raise typer.Exit(1)
        except PassiveReconError as e:
            logger.error(f"Erro no reconhecimento passivo: {e.message}", 
                        extra={"extra_data": {"error_type": "passive_recon"}})
            console.print(f"[red]Erro: Falha no reconhecimento passivo - {e.message}[/]")
            raise typer.Exit(1)
        except ZoneTransferError as e:
            logger.error(f"Erro na transferência de zona: {e.message}", 
                        extra={"extra_data": {"error_type": "zone_transfer"}})
            console.print(f"[red]Erro: Falha na transferência de zona - {e.message}[/]")
            raise typer.Exit(1)
        except TakeoverDetectionError as e:
            logger.error(f"Erro na detecção de takeover: {e.message}", 
                        extra={"extra_data": {"error_type": "takeover"}})
            console.print(f"[red]Erro: Falha na detecção de takeover - {e.message}[/]")
            raise typer.Exit(1)
        except CataclysmDNSError as e:
            logger.error(f"Erro do CataclysmDNS: {e.message}", 
                        extra={"extra_data": {"error_type": "generic"}})
            console.print(f"[red]Erro: {e.message}[/]")
            raise typer.Exit(1)
        except KeyboardInterrupt:
            logger.info("Operação cancelada pelo usuário")
            console.print("\n[yellow]Operação cancelada pelo usuário[/]")
            raise typer.Exit(0)
        except Exception as e:
            logger.exception(f"Erro não tratado: {e}")
            console.print(f"[red]Erro inesperado: {e}[/]")
            console.print("[yellow]Considere reportar este erro com --debug[/]")
            raise typer.Exit(1)
    return wrapper


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

if "--help" in sys.argv or "-h" in sys.argv:
     show_banner()


def validate_domain(domain: str) -> bool:
    """Valida se o domínio tem formato válido"""
    import re
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not bool(re.match(pattern, domain)):
        raise InvalidConfigurationError(f"Domínio inválido: {domain}")
    return True


def validate_ip(ip: str) -> bool:
    """Valida se é um endereço IP válido"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        raise InvalidConfigurationError(f"Endereço IP inválido: {ip}")


def save_results(results: dict, output_format: str, output_file: str):
    """Salva os resultados no formato especificado"""
    try:
        with OperationLogger(f"save_results_{output_format}", logger) as op_logger:
            op_logger.add_metric("output_file", output_file)
            op_logger.add_metric("results_count", len(results))
            
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
            else:
                raise InvalidConfigurationError(f"Formato de output não suportado: {output_format}")
            
            console.print(f"[green]Resultados salvos em: {output_file}[/]")
    except IOError as e:
        raise CataclysmDNSError(f"Erro ao salvar resultados: {e}")


def display_results_table(results: dict):
    """Exibe os resultados em formato de tabela"""
    table = Table(title="🔍 Resultados da Enumeração", show_header=True, header_style="bold cyan")
    table.add_column("Subdomínio", style="green", width=40)
    table.add_column("Tipo", style="magenta", width=10)
    table.add_column("Valor", style="white", width=40)
    
    for fqdn, records in results.items():
        for rdtype, values in records.items():
            for value in values:
                table.add_row(fqdn, rdtype, value)
    
    console.print()
    console.print(table)
    console.print()


def display_summary(results: dict, wildcard_detected: bool):
    """Exibe um resumo dos resultados"""
    total_subdomains = len(results)
    total_records = sum(len(records) for records in results.values())
    
    summary = Panel(
        f"""
[green]✓[/] Total de subdomínios encontrados: [bold]{total_subdomains}[/]
[blue]ℹ[/] Total de registros DNS: [bold]{total_records}[/]
[yellow]⚠[/] Wildcard DNS: [bold]{'Detectado' if wildcard_detected else 'Não detectado'}[/]
""",
        title="📊 Sumário",
        border_style="blue"
    )
    
    console.print(summary)


@app.command()
@handle_specific_errors
def enum(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    wordlist: Annotated[str, typer.Option(help="Wordlist de subdomínios")] = "wordlists/subdomains.txt",
    nameserver: Annotated[Optional[str], typer.Option(help="Servidor DNS customizado (IP)")] = None,
    workers: Annotated[int, typer.Option(help="Número de workers paralelos")] = 20,
    output: Annotated[Optional[str], typer.Option(help="Arquivo de output")] = None,
    format: Annotated[str, typer.Option(help="Formato do output (json, csv)")] = "json",
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Modo verboso")] = False,
    rate_limit: Annotated[float, typer.Option(help="Requisições por segundo")] = 10.0,
    timeout: Annotated[float, typer.Option(help="Timeout por requisição em segundos")] = 5.0,
):
    """
    Enumeração avançada de subdomínios com múltiplos tipos de registro
    e detecção de wildcard.
    """
    with OperationLogger("enum_command", logger) as op_logger:
        op_logger.add_metric("domain", domain)
        op_logger.add_metric("wordlist", wordlist)
        
        validate_domain(domain)
        
        if nameserver and not validate_ip(nameserver):
            raise InvalidConfigurationError(f"Endereço IP inválido para nameserver: {nameserver}")
        
        if not Path(wordlist).exists():
            raise WordlistError(f"Wordlist não encontrada: {wordlist}")
        
        # Configura rate limiter
        rate_limiter = RateLimiter(RateLimitConfig(requests_per_second=rate_limit))
        
        # Cria resolver (temporariamente sem cache)
        resolver = create_enhanced_resolver(
            nameservers=[nameserver] if nameserver else None,
            timeout=timeout
        )
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"[cyan]Enumerando {domain}...", total=None)
            
            try:
                subs = [l.strip() for l in open(wordlist, encoding="utf-8") if l.strip()]
            except IOError as e:
                raise WordlistError(f"Erro ao ler wordlist: {e}")
            
            subs = generate_permutations(subs, limit_permutations=None)
            
            if verbose:
                console.print(f"[dim]Carregados {len(subs)} subdomínios para teste[/]")
                console.print(f"[dim]Rate limit: {rate_limit} req/s[/]")
                console.print(f"[dim]Timeout: {timeout}s[/]")
            
            console.print(f"[cyan]Enumerando {domain}...[/cyan]")
            console.print()  # Linha em branco
            
            types = ["A", "AAAA", "MX", "TXT", "PTR"]
            
            # Executa resolução com output em tempo real
            results = asyncio.run(enum_subdomains_core(
                domain=domain,
                subs=subs,
                types=types,
                nameserver=nameserver,
                workers=workers
            ))
            
            progress.update(task, completed=True)
        
        wildcard_detected = detect_wildcard(domain)
        
        # Exibe os resultados finais
        if results:
            console.print()  # Linha em branco antes da tabela
            display_results_table(results)
            display_summary(results, wildcard_detected)
            op_logger.add_metric("results_count", len(results))
        else:
            console.print("[yellow]Nenhum subdomínio encontrado.[/]")
            if wildcard_detected:
                console.print("[yellow]⚠️  Isso pode ser devido à detecção de Wildcard DNS.[/]")
        
        if output:
            save_results(results, format, output)


@app.command()
@handle_specific_errors
def resolve(
    name: Annotated[str, typer.Option(help="FQDN ou IP para resolver")],
    record: Annotated[str, typer.Option(help="Tipo de registro")] = "A",
    nameserver: Annotated[Optional[str], typer.Option(help="Servidor DNS customizado")] = None,
    timeout: Annotated[float, typer.Option(help="Timeout em segundos")] = 2.0,
):
    """Resolve um único registro DNS de forma síncrona."""
    with OperationLogger("resolve_command", logger) as op_logger:
        op_logger.add_metric("name", name)
        op_logger.add_metric("record_type", record)
        
        resolver = create_enhanced_resolver(
            nameservers=[nameserver] if nameserver else None,
            timeout=timeout
        )
        
        # Executa resolução assíncroma usando run_until_complete
        loop = asyncio.get_event_loop()
        values = loop.run_until_complete(
            resolver.resolve_with_enhanced_error_handling(name, record)
        )
        
        if values:
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Registro", style="green")
            table.add_column("Tipo", style="magenta")
            table.add_column("Valor", style="white")
            
            for v in values:
                table.add_row(name, record, v)
            
            console.print()
            console.print(table)
            console.print()
            op_logger.add_metric("results_count", len(values))
        else:
            console.print(f"[red]❌ Sem resposta para {name} {record}[/]")


@app.command()
@handle_specific_errors
@retry_with_backoff(DNS_RETRY_CONFIG)
def zone_transfer(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    nameserver: Annotated[str, typer.Option(help="Servidor DNS autoritativo")],
    output: Annotated[Optional[str], typer.Option(help="Arquivo de output")] = None,
):
    """Tenta transferência de zona (AXFR)"""
    with OperationLogger("zone_transfer_command", logger) as op_logger:
        op_logger.add_metric("domain", domain)
        op_logger.add_metric("nameserver", nameserver)
        
        validate_domain(domain)
        
        if not validate_ip(nameserver) and not validate_domain(nameserver):
            raise InvalidConfigurationError(f"Nameserver inválido: {nameserver}")
        
        try:
            records = attempt_axfr(domain, nameserver)
        except Exception as e:
            raise ZoneTransferError(f"Falha na transferência de zona: {e}")
        
        if records:
            op_logger.add_metric("records_found", sum(len(recs) for recs in records.values()))
        else:
            console.print()  # Linha em branco
            console.print("[yellow]Nenhum registro encontrado na transferência de zona.[/]")
        
        if output and records:
            save_results({"zone_transfer": records}, "json", output)


@app.command()
@handle_specific_errors
def brute(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    wordlist: Annotated[str, typer.Option(help="Wordlist para brute force")] = "wordlists/subdomains.txt",
    workers: Annotated[int, typer.Option(help="Workers assíncronos")] = 50,
    output: Annotated[Optional[str], typer.Option(help="Arquivo de output")] = None,
    progress: Annotated[bool, typer.Option(help="Mostrar barra de progresso")] = True,
):
    """Brute force de subdomínios via wordlist"""
    with OperationLogger("brute_command", logger) as op_logger:
        op_logger.add_metric("domain", domain)
        op_logger.add_metric("wordlist", wordlist)
        
        validate_domain(domain)
        
        if not Path(wordlist).exists():
            raise WordlistError(f"Wordlist não encontrada: {wordlist}")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=not progress,
        ) as progress_bar:
            task = progress_bar.add_task(f"[cyan]Brute force em {domain}...", total=None)
            
            try:
                results = asyncio.run(brute_force(domain, wordlist, workers))
            except Exception as e:
                raise CataclysmDNSError(f"Erro durante brute force: {e}")
            
            progress_bar.update(task, completed=True)
        
        if results:
            display_results_table(results)
            console.print(f"\n[green]Brute force: {len(results)} subdomínios encontrados.[/]")
            op_logger.add_metric("results_count", len(results))
        else:
            console.print("[yellow]Nenhum subdomínio encontrado no brute force.[/]")
        
        if output:
            save_results(results, "json", output)


@app.command()
@handle_specific_errors
def dnssec(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Modo verboso")] = False,
):
    """Verifica DNSSEC"""
    with OperationLogger("dnssec_command", logger) as op_logger:
        op_logger.add_metric("domain", domain)
        
        validate_domain(domain)
        
        try:
            enabled = check_dnssec(domain)
        except Exception as e:
            raise CataclysmDNSError(f"Erro ao verificar DNSSEC: {e}")
        
        console.print()  # Linha em branco para separação
        op_logger.add_metric("dnssec_enabled", enabled)


@app.command()
@handle_specific_errors
def monitor_dns(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    interval: Annotated[int, typer.Option(help="Intervalo em segundos")] = 300,
    output: Annotated[Optional[str], typer.Option(help="Arquivo de log")] = None,
):
    """Monitora mudanças de registros DNS"""
    with OperationLogger("monitor_command", logger) as op_logger:
        op_logger.add_metric("domain", domain)
        op_logger.add_metric("interval", interval)
        
        validate_domain(domain)
        
        if output:
            # Configurar logger para arquivo
            file_handler = logging.FileHandler(output)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
            logging.getLogger("monitoring").addHandler(file_handler)
        
        try:
            monitor(domain, interval)
        except Exception as e:
            raise CataclysmDNSError(f"Erro durante monitoramento: {e}")


@app.command()
@handle_specific_errors
def passive(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    output: Annotated[Optional[str], typer.Option(help="Arquivo de output")] = None,
    format: Annotated[str, typer.Option(help="Formato do output (json, csv, txt)")] = "json",
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Modo verboso")] = False,
    debug: Annotated[bool, typer.Option("--debug", help="Salvar HTML para análise")] = False,
):
    """
    Realiza reconhecimento passivo de DNS usando múltiplas fontes
    """
    with OperationLogger("passive_command", logger) as op_logger:
        op_logger.add_metric("domain", domain)
        
        validate_domain(domain)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"[cyan]Reconhecimento passivo em {domain}...", total=None)
            
            try:
                recon = PassiveRecon(debug=debug)
                results = asyncio.run(recon.gather_subdomains(domain))
            except Exception as e:
                raise PassiveReconError(f"Erro durante reconhecimento passivo: {e}")
            
            progress.update(task, completed=True)
        
        # Exibir resultados
        if results['subdomains']:
            stats_table = Table(title="📊 Estatísticas por Fonte", show_header=True, header_style="bold blue")
            stats_table.add_column("Fonte", style="cyan", width=20)
            stats_table.add_column("Subdomínios", style="green", justify="right")
            
            for source, count in results['stats']['sources'].items():
                stats_table.add_row(source, str(count) if count > 0 else "-")
            
            console.print()
            console.print(stats_table)
            console.print()
            
            sub_table = Table(title="🔍 Subdomínios Encontrados", show_header=True, header_style="bold green")
            sub_table.add_column("#", style="dim", width=6)
            sub_table.add_column("Subdomínio", style="green")
            
            for i, sub in enumerate(results['subdomains'], 1):
                sub_table.add_row(str(i), sub)
            
            console.print(sub_table)
            console.print()
            console.print(f"[green]✓ Total: {len(results['subdomains'])} subdomínios únicos encontrados[/]")
            
            op_logger.add_metric("subdomains_found", len(results['subdomains']))
        else:
            console.print("[yellow]Nenhum subdomínio encontrado[/]")
        
        if output:
            save_results(results, format, output)


@app.command()
@handle_specific_errors
def takeover(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    wordlist: Annotated[str, typer.Option(help="Wordlist de subdomínios")] = "wordlists/subdomains.txt",
    output: Annotated[Optional[str], typer.Option(help="Arquivo de output")] = None,
    workers: Annotated[int, typer.Option(help="Workers paralelos")] = 10,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Modo verboso")] = False,
):
    """
    Detecta vulnerabilidades de subdomain takeover
    """
    with OperationLogger("takeover_command", logger) as op_logger:
        op_logger.add_metric("domain", domain)
        op_logger.add_metric("wordlist", wordlist)
        
        validate_domain(domain)
        
        if not Path(wordlist).exists():
            raise WordlistError(f"Wordlist não encontrada: {wordlist}")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"[cyan]Detectando takeover em {domain}...", total=None)
            
            try:
                subs = load_wordlist(wordlist)
                subdomains = [f"{sub}.{domain}" for sub in subs]
            except Exception as e:
                raise WordlistError(f"Erro ao carregar wordlist: {e}")
            
            if verbose:
                console.print(f"[dim]Verificando {len(subdomains)} subdomínios[/]")
            
            try:
                detector = SubdomainTakeoverDetector()
                results = asyncio.run(detector.scan_subdomains(subdomains, workers))
            except Exception as e:
                raise TakeoverDetectionError(f"Erro durante detecção de takeover: {e}")
            
            progress.update(task, completed=True)
        
        # Exibir resultados
        if results:
            table = Table(title="🚨 Vulnerabilidades de Subdomain Takeover", show_header=True, header_style="bold red")
            table.add_column("Subdomínio", style="green", width=30)
            table.add_column("Serviço", style="cyan", width=15)
            table.add_column("CNAME", style="yellow", width=30)
            table.add_column("Recomendação", style="white", width=50)
            
            for result in results:
                table.add_row(
                    result['subdomain'],
                    result['service'],
                    result['cname'],
                    result['recommendation']
                )
            
            console.print()
            console.print(table)
            console.print(f"\n[red]⚠️  {len(results)} vulnerabilidades encontradas![/]")
            
            op_logger.add_metric("vulnerabilities_found", len(results))
        else:
            console.print("[green]✓ Nenhuma vulnerabilidade de subdomain takeover encontrada[/]")
        
        if output:
            save_results({'takeover_vulnerabilities': results}, 'json', output)


@app.command()
@handle_specific_errors
def cache_stats():
    """Exibe estatísticas do cache"""
    stats = caching_system.get_all_stats()
    
    for cache_name, cache_stats in stats.items():
        stats_panel = Panel(
            f"""
[bold]Cache:[/] {cache_name}
[green]Hits:[/] {cache_stats['hits']}
[red]Misses:[/] {cache_stats['misses']}
[blue]Sets:[/] {cache_stats['sets']}
[yellow]Deletes:[/] {cache_stats['deletes']}
[cyan]Hit Rate:[/] {cache_stats['hit_rate']:.1%}
[dim]Last Reset:[/] {cache_stats['last_reset']}
""",
            title=f"📊 Estatísticas - {cache_name}",
            border_style="blue"
        )
        console.print(stats_panel)
        console.print()


@app.command()
@handle_specific_errors
def cache_clear(
    cache_type: Annotated[Optional[str], typer.Option(help="Tipo específico de cache para limpar")] = None,
    force: Annotated[bool, typer.Option("--force", "-f", help="Força limpeza sem confirmação")] = False
):
    """Limpa o cache (todo ou específico)"""
    if cache_type:
        if cache_type not in caching_system.cache_map:
            console.print(f"[red]Tipo de cache inválido: {cache_type}[/]")
            console.print(f"[yellow]Tipos válidos: {', '.join(caching_system.cache_map.keys())}[/]")
            raise typer.Exit(1)
        
        if not force:
            confirm = typer.confirm(f"Tem certeza que deseja limpar o cache '{cache_type}'?")
            if not confirm:
                console.print("[yellow]Operação cancelada[/]")
                return
        
        asyncio.run(caching_system.get_cache(cache_type).clear())
        console.print(f"[green]Cache '{cache_type}' limpo com sucesso[/]")
    else:
        if not force:
            confirm = typer.confirm("Tem certeza que deseja limpar TODO o cache?")
            if not confirm:
                console.print("[yellow]Operação cancelada[/]")
                return
        
        asyncio.run(caching_system.clear_all())
        console.print("[green]Todo o cache foi limpo com sucesso[/]")


@app.command()
@handle_specific_errors
def cache_reset_stats():
    """Reseta as estatísticas do cache"""
    caching_system.reset_all_stats()
    console.print("[green]Estatísticas do cache resetadas com sucesso[/]")


@app.callback()
def main(
    debug: Annotated[bool, typer.Option("--debug", help="Ativar modo debug")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Modo silencioso")] = False,
    no_cache: Annotated[bool, typer.Option("--no-cache", help="Desabilitar cache temporariamente")] = False,
):
    """CataclysmDNS - Ferramenta avançada de pentest DNS"""
    # Configura limpeza automática de logs
    setup_log_cleaning()
    
    # Configura o logging global
    if not debug:
        # Desabilita todos os loggers raiz para evitar output no console
        logging.basicConfig(level=logging.CRITICAL)
        logging.getLogger().handlers = []
        # Também desabilita logging para bibliotecas específicas
        logging.getLogger("dns").setLevel(logging.CRITICAL)
        logging.getLogger("asyncio").setLevel(logging.CRITICAL)
        logging.getLogger("aiohttp").setLevel(logging.CRITICAL)
    
    # Mostra o banner apenas se não estiver no modo silencioso
    if "--help" not in sys.argv and not quiet:
        show_banner()
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    if quiet:
        console.quiet = True
    if no_cache:
        console.print("[yellow]Cache ainda não implementado[/]")


if __name__ == "__main__":
    app()