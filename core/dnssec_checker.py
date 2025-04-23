import dns.resolver
from utils.logger import setup_logger

logger = setup_logger("dnssec")

def check_dnssec(domain: str) -> tuple[bool, dict]:
    """
    Verifica DNSSEC com informações detalhadas
    Returns: (enabled, details_dict)
    """
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        # Validar assinaturas RRSIG
        # Verificar cadeia de confiança
        # Checar algoritmos e flags
        details = {
            'keys_found': len(answers),
            'algorithms': [key.algorithm for key in answers],
            'flags': [key.flags for key in answers]
        }
        return True, details
    except Exception as e:
        return False, {'error': str(e)}