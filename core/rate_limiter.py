import time
import asyncio
from collections import deque
from typing import Dict, Deque
from dataclasses import dataclass
from utils.logger import setup_logger

logger = setup_logger("rate_limiter")

@dataclass
class RateLimitConfig:
    requests_per_second: float = 10.0  # Máximo de requisições por segundo
    burst_size: int = 20  # Tamanho do burst
    min_delay: float = 0.1  # Delay mínimo entre requisições
    adaptive: bool = True  # Habilita rate limiting adaptativo

class RateLimiter:
    """Rate limiter inteligente com burst e adaptação dinâmica"""
    
    def __init__(self, config: RateLimitConfig = RateLimitConfig()):
        self.config = config
        self.tokens = config.burst_size
        self.last_update = time.time()
        self.request_times: Deque[float] = deque(maxlen=100)
        self.error_count = 0
        self.last_error_time = 0.0
    
    async def acquire(self):
        """Aguarda até que seja permitido fazer uma requisição"""
        now = time.time()
        
        # Atualiza tokens baseado no tempo passado
        time_passed = now - self.last_update
        self.tokens = min(
            self.config.burst_size,
            self.tokens + time_passed * self.config.requests_per_second
        )
        self.last_update = now
        
        # Aguarda se não há tokens disponíveis
        if self.tokens < 1:
            sleep_time = (1 - self.tokens) / self.config.requests_per_second
            await asyncio.sleep(sleep_time)
            self.tokens = 0
        else:
            self.tokens -= 1
        
        # Aplica delay mínimo
        if self.request_times and (now - self.request_times[-1]) < self.config.min_delay:
            await asyncio.sleep(self.config.min_delay)
        
        self.request_times.append(now)
        
        # Rate limiting adaptativo
        if self.config.adaptive:
            await self._adaptive_delay()
    
    async def _adaptive_delay(self):
        """Ajusta o rate limit baseado em erros e respostas"""
        now = time.time()
        
        # Se há muitos erros recentes, aumenta o delay
        if self.error_count > 5 and (now - self.last_error_time) < 60:
            extra_delay = min(2.0, 0.1 * self.error_count)
            await asyncio.sleep(extra_delay)
            logger.warning(f"Rate limiting adaptativo: delay extra de {extra_delay}s")
    
    def report_error(self):
        """Registra um erro para o rate limiting adaptativo"""
        self.error_count += 1
        self.last_error_time = time.time()
    
    def report_success(self):
        """Registra sucesso para reduzir o rate limiting"""
        if self.error_count > 0:
            self.error_count = max(0, self.error_count - 0.5)