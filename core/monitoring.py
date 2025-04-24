import dns.resolver
import dns.asyncresolver
import asyncio
import json
from datetime import datetime
from rich.console import Console
from utils.logger import setup_logger

logger = setup_logger("monitoring")
console = Console()

async def fetch_records_async(domain: str, record_type: str = "A") -> set[str]:
    """Busca registros DNS de forma assíncrona"""
    resolver = dns.asyncresolver.Resolver()
    try:
        answers = await resolver.resolve(domain, record_type)
        return {rdata.to_text() for rdata in answers}
    except Exception as e:
        logger.error(f"Erro ao buscar registros DNS: {e}")
        return set()

async def monitor_async(domain: str, interval: int = 300, types: list[str] = ["A", "MX", "TXT"]):
    """
    Monitora alterações de registros DNS de forma assíncrona com output em tempo real
    """
    console.print(f"[cyan]Iniciando monitoramento de {domain}...[/cyan]")
    console.print(f"[blue]Intervalo: {interval} segundos[/blue]")
    console.print(f"[blue]Tipos: {', '.join(types)}[/blue]")
    console.print()  # Linha em branco
    
    last_records = {}
    for record_type in types:
        last_records[record_type] = await fetch_records_async(domain, record_type)
        console.print(f"[green][+][/green] Estado inicial {record_type}: {last_records[record_type]}")
    
    console.print()  # Linha em branco
    
    while True:
        await asyncio.sleep(interval)
        
        console.print(f"[cyan][{datetime.now().strftime('%H:%M:%S')}] Verificando mudanças...[/cyan]")
        
        changes_detected = False
        
        for record_type in types:
            current = await fetch_records_async(domain, record_type)
            
            if current != last_records[record_type]:
                changes_detected = True
                added = current - last_records[record_type]
                removed = last_records[record_type] - current
                
                if added:
                    console.print(f"[green][↑][/green] Novos registros {record_type}: {added}")
                if removed:
                    console.print(f"[red][↓][/red] Registros {record_type} removidos: {removed}")
                
                last_records[record_type] = current
        
        if changes_detected:
            console.print(f"[yellow][!][/yellow] Mudanças detectadas em {domain} às {datetime.now()}")
        else:
            console.print(f"[green][✓][/green] Sem mudanças em {domain}")
        
        console.print()  # Linha em branco

def monitor(domain: str, interval: int = 300):
    """Wrapper síncrono que chama a versão assíncrona"""
    asyncio.run(monitor_async(domain, interval))