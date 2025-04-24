import dns.query
import dns.zone
from dns.exception import DNSException
from rich.console import Console
from utils.logger import setup_logger

logger = setup_logger("zone_transfer")
console = Console()

def attempt_axfr(domain: str, nameserver: str) -> dict[str, str]:
    """
    Tenta transferência de zona (AXFR) no servidor especificado.
    """
    console.print(f"[cyan]Tentando transferência de zona (AXFR) em {nameserver}...[/cyan]")
    console.print()  # Linha em branco
    
    try:
        z = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=10))
        records = {}
        for name, node in z.nodes.items():
            rdatasets = node.rdatasets
            for rdataset in rdatasets:
                for rdata in rdataset:
                    fqdn = f"{name}.{domain}"
                    record_type = str(rdataset.rdtype)
                    records.setdefault(record_type, []).append(f"{fqdn} -> {rdata}")
                    # Mostra resultado em tempo real
                    console.print(f"[green][+][/green] {fqdn} -> {rdata} ({record_type})")
        
        logger.info(f"[+] AXFR bem-sucedido em {nameserver}")
        return records
    except DNSException as e:
        logger.warning(f"[-] AXFR falhou em {nameserver}: {e}")
        console.print(f"[red][-][/red] AXFR falhou em {nameserver}: {e}")
        return {}