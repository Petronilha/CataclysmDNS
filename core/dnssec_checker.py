import dns.resolver
from utils.logger import setup_logger

logger = setup_logger("dnssec")

def check_dnssec(domain: str) -> bool:
    """
    Verifica se o domínio possui DNSSEC habilitado.
    """
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        enabled = bool(answers)
        logger.info(f"[+] DNSSEC {'habilitado' if enabled else 'não encontrado'} para {domain}")
        return enabled
    except Exception as e:
        logger.warning(f"[-] Erro ao verificar DNSSEC em {domain}: {e}")
        return False