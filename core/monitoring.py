import dns.resolver
import time
from utils.logger import setup_logger

logger = setup_logger("monitoring")

def fetch_records(domain: str, record_type: str = "A") -> set[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return {rdata.to_text() for rdata in answers}
    except Exception:
        return set()

def monitor(domain: str, interval: int = 300):
    """
    Monitora alterações de registros a cada `interval` segundos.
    """
    last = fetch_records(domain)
    logger.info(f"Inicial: {last}")
    while True:
        time.sleep(interval)
        current = fetch_records(domain)
        if current != last:
            logger.warning(f"[!] Mudança detectada: {last} -> {current}")
            last = current
        else:
            logger.info(f"[ ] Sem mudanças em {domain}")