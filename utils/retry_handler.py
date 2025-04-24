# utils/retry_handler.py
import asyncio
import aiohttp
import functools
import random
import time
import dns
from typing import Callable, Type, Tuple, Union, Optional
from utils.logger import setup_logger
from core.exceptions import CataclysmDNSError, RateLimitExceededError, NetworkError

logger = setup_logger("retry_handler")

class RetryConfig:
    """Configuração para retry"""
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
        exceptions: Tuple[Type[Exception], ...] = (Exception,)
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
        self.exceptions = exceptions

def calculate_backoff(
    attempt: int,
    base_delay: float,
    max_delay: float,
    exponential_base: float,
    jitter: bool
) -> float:
    """Calcula o tempo de backoff com jitter opcional"""
    delay = min(base_delay * (exponential_base ** attempt), max_delay)
    
    if jitter:
        # Adiciona jitter entre 0% e 25% do delay
        jitter_amount = delay * 0.25 * random.random()
        delay += jitter_amount
    
    return delay

def retry_with_backoff(config: RetryConfig = None):
    """Decorator para retry com backoff exponencial"""
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(config.max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                
                except config.exceptions as e:
                    last_exception = e
                    
                    if attempt == config.max_retries:
                        logger.error(f"Máximo de tentativas atingido para {func.__name__}: {e}")
                        raise
                    
                    # Tratamento especial para RateLimitExceededError
                    if isinstance(e, RateLimitExceededError) and e.retry_after:
                        delay = e.retry_after
                    else:
                        delay = calculate_backoff(
                            attempt,
                            config.base_delay,
                            config.max_delay,
                            config.exponential_base,
                            config.jitter
                        )
                    
                    logger.warning(
                        f"Tentativa {attempt + 1}/{config.max_retries} falhou para {func.__name__}: {e}. "
                        f"Aguardando {delay:.2f}s antes de tentar novamente..."
                    )
                    
                    await asyncio.sleep(delay)
            
            # Não deveria chegar aqui, mas por segurança
            if last_exception:
                raise last_exception
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(config.max_retries + 1):
                try:
                    return func(*args, **kwargs)
                
                except config.exceptions as e:
                    last_exception = e
                    
                    if attempt == config.max_retries:
                        logger.error(f"Máximo de tentativas atingido para {func.__name__}: {e}")
                        raise
                    
                    # Tratamento especial para RateLimitExceededError
                    if isinstance(e, RateLimitExceededError) and e.retry_after:
                        delay = e.retry_after
                    else:
                        delay = calculate_backoff(
                            attempt,
                            config.base_delay,
                            config.max_delay,
                            config.exponential_base,
                            config.jitter
                        )
                    
                    logger.warning(
                        f"Tentativa {attempt + 1}/{config.max_retries} falhou para {func.__name__}: {e}. "
                        f"Aguardando {delay:.2f}s antes de tentar novamente..."
                    )
                    
                    time.sleep(delay)
            
            # Não deveria chegar aqui, mas por segurança
            if last_exception:
                raise last_exception
        
        # Retorna o wrapper apropriado baseado se a função é async ou não
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

# Configurações pré-definidas para diferentes tipos de operação
NETWORK_RETRY_CONFIG = RetryConfig(
    max_retries=5,
    base_delay=1.0,
    max_delay=30.0,
    exceptions=(NetworkError, ConnectionError, TimeoutError)
)

DNS_RETRY_CONFIG = RetryConfig(
    max_retries=3,
    base_delay=0.5,
    max_delay=5.0,
    exceptions=(dns.exception.Timeout, dns.resolver.NoNameservers)
)

API_RETRY_CONFIG = RetryConfig(
    max_retries=3,
    base_delay=2.0,
    max_delay=60.0,
    exceptions=(aiohttp.ClientError, RateLimitExceededError)
)