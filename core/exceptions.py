"""
Exceções customizadas para o CataclysmDNS
"""

class CataclysmDNSError(Exception):
    """Classe base para todas as exceções do CataclysmDNS"""
    def __init__(self, message: str, original_error: Exception = None):
        self.message = message
        self.original_error = original_error
        super().__init__(self.message)

class DNSResolutionError(CataclysmDNSError):
    """Erro durante a resolução de DNS"""
    pass

class DNSTimeoutError(DNSResolutionError):
    """Timeout específico durante resolução de DNS"""
    def __init__(self, message: str, query_type: str, domain: str, timeout: float, original_error: Exception = None):
        self.query_type = query_type
        self.domain = domain
        self.timeout = timeout
        super().__init__(message, original_error)

class ZoneTransferError(CataclysmDNSError):
    """Erro durante transferência de zona"""
    pass

class RateLimitExceededError(CataclysmDNSError):
    """Limite de taxa excedido"""
    def __init__(self, message: str, retry_after: float = None):
        self.retry_after = retry_after
        super().__init__(message)

class InvalidConfigurationError(CataclysmDNSError):
    """Erro de configuração inválida"""
    pass

class PassiveReconError(CataclysmDNSError):
    """Erro durante reconhecimento passivo"""
    pass

class APIKeyError(PassiveReconError):
    """Erro relacionado a chaves de API"""
    pass

class WordlistError(CataclysmDNSError):
    """Erro ao processar wordlist"""
    pass

class NetworkError(CataclysmDNSError):
    """Erro de conexão de rede"""
    pass

class TakeoverDetectionError(CataclysmDNSError):
    """Erro durante detecção de takeover"""
    pass