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
from rich.table import Table
from rich.panel import Panel
from rich import box
from functools import wraps
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
    TakeoverDetectionError
)
from core.resolver_core import enum_subdomains_core
from utils.enhanced_logger import setup_enhanced_logger, OperationLogger
from utils.retry_handler import retry_with_backoff, DNS_RETRY_CONFIG
from utils.log_cleaner import setup_log_cleaning
from utils.wordlist_loader import load_wordlist

# Imports originais mantidos para compatibilidade
from core.resolver import (
    generate_permutations,
    detect_wildcard,
)
from core.zone_transfer import attempt_axfr

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
            raise typer.Exit(1)
    return wrapper


def show_banner():
    """Exibe o banner ASCII art da ferramenta com adaptação para dispositivos móveis"""
    import os
    from rich.console import Console
    
    console = Console()
    
    # Detecta tamanho do terminal
    try:
        terminal_width = os.get_terminal_size().columns
    except:
        # Fallback para terminais muito estreitos
        terminal_width = 30
    
    # Para terminais extremamente estreitos (como o da screenshot)
    if terminal_width < 35:
        # Versão extremamente simplificada para terminais muito estreitos
        banner = r"""
 ████ ████ ██ ██ █████
 █    █  █ ███  █    
 █    █  █ █ ██ █████
 █    █  █ █  █ █    
 ████ ████ █  █ █████
        """
        console.print(banner, style="bold cyan")
        console.print(" [yellow]CataclysmDNS[/]")
        console.print(" [dim white]v2.0[/]")
        return
    
    # Para terminais móveis, mas não tão estreitos
    if terminal_width < 60:
        banner = r"""
 ██████╗██████╗ ███╗   ██╗███████╗
 ██╔═══╝██╔══██╗████╗  ██║██╔════╝
 ██║    ██║  ██║██╔██╗ ██║███████╗
 ██║    ██║  ██║██║╚██╗██║╚════██║
 ╚████╗ ██████╔╝██║ ╚████║███████║
  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
        """
        console.print(banner, style="bold cyan")
        console.print(" [yellow]CataclysmDNS v2.0[/]")
        console.print(" [dim white]Por Petronilha[/]")
        return
    
    # Para telas médias
    if terminal_width < 80:
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
        console.print("         [yellow]Toolkit avançado de pentest DNS[/]")
        console.print("         [dim white]Versão 2.0 - Por Petronilha[/]")
        return
    
    # Banner padrão para desktop ou telas largas
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
    console.print("                [dim white]Versão 2.0 - Por Petronilha[/]")

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
    """Exibe os resultados em formato de tabela elegante"""
    table = Table(
        title="[bold cyan]🔍 Resultados da Enumeração DNS[/]", 
        show_header=True, 
        header_style="bold black on cyan",
        box=box.MINIMAL_DOUBLE_HEAD, # Estilo mais limpo, destacando o cabeçalho
        show_lines=True # Adiciona linhas sutis entre os resultados para facilitar a leitura
    )
    table.add_column("Subdomínio", style="bold green", width=40)
    table.add_column("Tipo", style="bold magenta", width=10, justify="center")
    table.add_column("Valor / Apontamento", style="white", width=45)
    
    for fqdn, records in results.items():
        for rdtype, values in records.items():
            for value in values:
                # Adiciona um marcador visual dependendo do tipo de registro
                icon = "🌐" if rdtype in ["A", "AAAA"] else "📧" if rdtype == "MX" else "📝" if rdtype == "TXT" else "➡️ "
                table.add_row(fqdn, f"{icon} {rdtype}", value)
    
    console.print()
    console.print(table)
    console.print()


def display_summary(results: dict, wildcard_detected: bool):
    """Exibe um resumo dos resultados com alinhamento perfeito"""
    total_subdomains = len(results)
    total_records = sum(len(records) for records in results.values())
    
    wildcard_text = "[bold red]Detectado[/]" if wildcard_detected else "[bold green]Não detectado[/]"
    
    # Cria uma grade invisível para garantir o alinhamento perfeito
    grid = Table.grid(padding=(0, 2)) # Espaçamento de 2 caracteres entre as colunas
    
    # Definindo as 3 colunas (Ícone, Descrição, Valor)
    grid.add_column(justify="center") 
    grid.add_column(justify="left", style="white")
    grid.add_column(justify="left")
    
    # Adicionando as linhas ao grid
    grid.add_row("[green]✓[/]", "Total de subdomínios únicos encontrados:", f"[bold white]{total_subdomains}[/]")
    grid.add_row("[blue]ℹ[/]", "Total de registros DNS extraídos:", f"[bold white]{total_records}[/]")
    grid.add_row("[yellow]⚠[/]", "Status de Wildcard DNS:", wildcard_text)
    
    # Colocando o grid dentro do Painel
    summary_panel = Panel(
        grid,
        title="[bold]📊 Sumário da Execução[/]",
        border_style="blue",
        box=box.ROUNDED, # Mantém as bordas arredondadas do painel externo
        padding=(1, 4)   # Dá um respiro interno (cima/baixo, esquerda/direita)
    )
    
    console.print()
    console.print(summary_panel)


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
    permutations: Annotated[bool, typer.Option("--permutations/--no-permutations", help="Gerar variações da wordlist (MUITO mais lento)")] = False,
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
        
        with Progress(TextColumn(" "), SpinnerColumn(speed=1.5), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task(f"[cyan]Enumerando {domain}...", total=None)
            
            subs = load_wordlist(wordlist)
            
            if not subs:
                raise WordlistError(f"Não foi possível carregar a wordlist '{wordlist}' ou ela está vazia/inválida.")
            
            if permutations:
                subs = generate_permutations(subs, limit_permutations=None)
                if verbose:
                    console.print("  \n[yellow]⚠️ Permutações ativadas: O scan será significativamente maior.[/]")
            
            if verbose:
                console.print(f"             [dim]Carregados {len(subs)} subdomínios para teste[/]")
                console.print(f"      [dim]Rate limit: {rate_limit} req/s | Timeout: {timeout}s | Workers: {workers}[/]")
                console.print()
            
            types = ["A", "AAAA", "MX", "TXT", "PTR"]
            
            results = asyncio.run(enum_subdomains_core(
                domain=domain, subs=subs, types=types, nameserver=nameserver, workers=workers, console=console
            ))
            
            progress.update(task, completed=True)
        
        wildcard_detected = detect_wildcard(domain) 
        
        if results:
            console.print()
            display_results_table(results)
            display_summary(results, wildcard_detected)
            op_logger.add_metric("results_count", len(results))
        else:
            console.print("[yellow]Nenhum subdomínio encontrado.[/]")
            if wildcard_detected:
                console.print("[yellow]⚠️  Isso pode ser devido à detecção de Wildcard DNS.[/]")
        
        if output:
            save_results(results, format, output)
        
        if output:
            save_results(results, format, output)


@app.command()
@handle_specific_errors
@retry_with_backoff(DNS_RETRY_CONFIG)
def zone_transfer(
    domain: Annotated[str, typer.Option(help="Domínio alvo")],
    nameserver: Annotated[str, typer.Option(help="Servidor DNS autoritativo (IP ou Hostname)")],
    output: Annotated[Optional[str], typer.Option(help="Arquivo de output")] = None,
):
    """Tenta transferência de zona (AXFR) aceitando IP ou URL"""
    with OperationLogger("zone_transfer_command", logger) as op_logger:
        op_logger.add_metric("domain", domain)
        op_logger.add_metric("nameserver", nameserver)
        
        validate_domain(domain)
        
        try:
            records = attempt_axfr(domain, nameserver)
        except Exception as e:
            raise ZoneTransferError(f"Falha na transferência de zona: {e}")
        
        if records:
            op_logger.add_metric("records_found", sum(len(recs) for recs in records.values()))
        else:
            console.print()  # Linha em branco
            # Já temos os avisos detalhados dentro da função, mas mantemos isso como fallback
            console.print("[dim yellow]Nenhum registro extraído.[/]")
        
        if output and records:
            save_results({"zone_transfer": records}, "json", output)


@app.callback()
def main(
    debug: Annotated[bool, typer.Option("--debug", help="Ativar modo debug")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Modo silencioso")] = False,
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
        #show_banner()
        pass
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    if quiet:
        console.quiet = True


if __name__ == "__main__":
    app()