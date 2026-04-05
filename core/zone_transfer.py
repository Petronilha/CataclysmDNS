import dns.query
import dns.zone
import dns.rdatatype
import dns.rdataclass
import socket  
from dns.exception import DNSException
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from utils.logger import setup_logger

logger = setup_logger("zone_transfer")
console = Console()

def attempt_axfr(domain: str, nameserver: str) -> dict[str, str]:
    """
    Tenta transferência de zona (AXFR) no servidor especificado.
    Resolve nomes de host para IPs automaticamente e exibe resultados em formato de tabela.
    """
    console.print(f"   [cyan]Preparando transferência de zona (AXFR) em {nameserver}...[/cyan]")
    
    try:
        # A MÁGICA: Converte automaticamente URL para IP
        ns_ip = socket.gethostbyname(nameserver)
        if ns_ip != nameserver:
            console.print(f"          [dim]Hostname resolvido com sucesso: {ns_ip}[/dim]\n")
        else:
            console.print(f"          [dim]Alvo direto: {ns_ip}[/dim]\n")
            
    except socket.gaierror:
        console.print(f"          [bold red][!] Falha crítica:[/bold red] Não foi possível encontrar o IP para o servidor '{nameserver}'.")
        return {}

    try:
        # O Ataque usando estritamente o IP
        z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
        records = {}
        
        # --- INÍCIO DA CONSTRUÇÃO VISUAL ---
        if z.nodes:  # Se a transferência trouxe resultados
            
            # 1. Painel de Sucesso
            success_msg = f"Transferência de zona (AXFR) executada com sucesso no servidor:\n[bold white]{nameserver} ({ns_ip})[/]"
            console.print()
            console.print(Panel(success_msg, title="[bold green]💀 Zona Comprometida[/]", border_style="green", box=box.HEAVY))
            console.print()

            # 2. Configuração da Tabela
            table = Table(
                show_header=True,
                header_style="bold black on green",
                box=box.SIMPLE_HEAVY,
                padding=(0, 2)
            )
            table.add_column("Subdomínio / Nome", style="bold green")
            table.add_column("TTL", style="dim white", justify="right")
            table.add_column("Classe", style="dim cyan", justify="center")
            table.add_column("Tipo", style="bold yellow", justify="center")
            table.add_column("Destino / IP", style="bright_white")

            # 3. Preenchimento dos dados
            for name, node in z.nodes.items():
                name_str = str(name)
                # O caractere '@' no DNS representa o domínio raiz
                if name_str == "@":
                    fqdn = domain
                else:
                    fqdn = f"{name_str}.{domain}"

                rdatasets = node.rdatasets
                for rdataset in rdatasets:
                    ttl = str(rdataset.ttl)
                    rdclass = dns.rdataclass.to_text(rdataset.rdclass)
                    record_type = dns.rdatatype.to_text(rdataset.rdtype)
                    
                    for rdata in rdataset:
                        valor = str(rdata)
                        
                        # Alimenta o dicionário interno do seu código
                        records.setdefault(record_type, []).append(f"{fqdn} -> {valor}")
                        
                        # Formatação de cores do Tipo para a tabela
                        if record_type in ["A", "AAAA"]:
                            tipo_fmt = f"[green]{record_type}[/]"
                        elif record_type == "CNAME":
                            tipo_fmt = f"[yellow]{record_type}[/]"
                        elif record_type == "TXT":
                            tipo_fmt = f"[magenta]{record_type}[/]"
                        else:
                            tipo_fmt = f"[cyan]{record_type}[/]"

                        # Adiciona a linha visualmente
                        table.add_row(fqdn, ttl, rdclass, tipo_fmt, valor)
            
            # Imprime a tabela perfeitamente alinhada
            console.print(table)
            console.print()
        # --- FIM DA CONSTRUÇÃO VISUAL ---

        logger.info(f"[+] AXFR bem-sucedido em {nameserver} ({ns_ip})")
        return records
        
    except DNSException as e:
        console.print(f"[red][-][/red] Servidor configurado corretamente. AXFR recusado em {nameserver}.")
        return {}
    except Exception as e:
        console.print(f"[red][-][/red] Erro de conexão ao tentar AXFR (Timeout ou porta fechada).")
        return {}