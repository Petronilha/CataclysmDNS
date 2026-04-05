import dns.query
import dns.zone
import dns.rdatatype
import socket  
from dns.exception import DNSException
from rich.console import Console
from utils.logger import setup_logger

logger = setup_logger("zone_transfer")
console = Console()

def attempt_axfr(domain: str, nameserver: str) -> dict[str, str]:
    """
    Tenta transferência de zona (AXFR) no servidor especificado.
    Resolve nomes de host para IPs automaticamente.
    """
    console.print(f"[cyan]Preparando transferência de zona (AXFR) em {nameserver}...[/cyan]")
    
    try:
        # A MÁGICA: Converte automaticamente URL para IP
        ns_ip = socket.gethostbyname(nameserver)
        if ns_ip != nameserver:
            console.print(f"[dim]Hostname resolvido com sucesso: {ns_ip}[/dim]\n")
        else:
            console.print(f"[dim]Alvo direto: {ns_ip}[/dim]\n")
            
    except socket.gaierror:
        console.print(f"[bold red][!] Falha crítica:[/bold red] Não foi possível encontrar o IP para o servidor '{nameserver}'.")
        return {}

    try:
        # O Ataque usando estritamente o IP
        z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
        records = {}
        
        for name, node in z.nodes.items():
            rdatasets = node.rdatasets
            for rdataset in rdatasets:
                record_type = dns.rdatatype.to_text(rdataset.rdtype)
                for rdata in rdataset:
                    fqdn = f"{name}.{domain}"
                    records.setdefault(record_type, []).append(f"{fqdn} -> {rdata}")
                    console.print(f"[green][+][/green] {fqdn} -> {rdata} ({record_type})")
        
        logger.info(f"[+] AXFR bem-sucedido em {nameserver} ({ns_ip})")
        return records
        
    except DNSException as e:
        console.print(f"[red][-][/red] Servidor configurado corretamente. AXFR recusado em {nameserver}.")
        return {}
    except Exception as e:
        console.print(f"[red][-][/red] Erro de conexão ao tentar AXFR (Timeout ou porta fechada).")
        return {}