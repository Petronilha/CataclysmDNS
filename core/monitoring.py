import dns.resolver
import dns.asyncresolver
import asyncio
import json
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger("monitoring")

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
    Monitora alterações de registros DNS de forma assíncrona
    """
    last_records = {}
    for record_type in types:
        last_records[record_type] = await fetch_records_async(domain, record_type)
    
    logger.info(f"Estado inicial: {last_records}")
    
    while True:
        await asyncio.sleep(interval)
        
        changes_detected = False
        
        for record_type in types:
            current = await fetch_records_async(domain, record_type)
            
            if current != last_records[record_type]:
                changes_detected = True
                added = current - last_records[record_type]
                removed = last_records[record_type] - current
                
                if added:
                    logger.warning(f"[↑] Novos registros {record_type}: {added}")
                if removed:
                    logger.warning(f"[↓] Registros {record_type} removidos: {removed}")
                
                last_records[record_type] = current
        
        if changes_detected:
            logger.warning(f"[!] Mudanças detectadas em {domain} às {datetime.now()}")
        else:
            logger.info(f"[✓] Sem mudanças em {domain}")

def fetch_records(domain: str, record_type: str = "A") -> set[str]:
    """Versão síncrona mantida para compatibilidade"""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return {rdata.to_text() for rdata in answers}
    except Exception:
        return set()

def monitor(domain: str, interval: int = 300):
    """Wrapper síncrono que chama a versão assíncrona"""
    asyncio.run(monitor_async(domain, interval))