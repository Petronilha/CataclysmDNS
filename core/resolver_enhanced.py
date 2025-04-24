import dns.asyncresolver
import dns.resolver
import asyncio
from typing import Optional, Dict, List, Set
from asyncio import Semaphore

from core.exceptions import DNSResolutionError, DNSTimeoutError, NetworkError
from utils.retry_handler import retry_with_backoff, DNS_RETRY_CONFIG
from utils.enhanced_logger import setup_enhanced_logger, OperationLogger
from core.rate_limiter import RateLimiter
logger = setup_enhanced_logger(
    "resolver", 
    json_file="logs/dns_operations.log", 
    console_output=False,
    level="DEBUG"  # Logs detalhados vão para o arquivo, mas não para o console
)

class EnhancedDNSResolver:
    """Resolver DNS aprimorado com tratamento de erros robusto"""
    
    def __init__(self, nameservers: Optional[List[str]] = None, timeout: float = 5.0):
        self.nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]
        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver(configure=False)
        self.resolver.nameservers = self.nameservers
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
    
    @retry_with_backoff(DNS_RETRY_CONFIG)
    async def resolve_with_enhanced_error_handling(
        self,
        domain: str,
        record_type: str
    ) -> List[str]:
        """
        Resolve um registro DNS com tratamento de erro aprimorado
        """
        try:
            with OperationLogger(f"dns_resolve_{record_type}", logger) as op_logger:
                op_logger.add_metric("domain", domain)
                op_logger.add_metric("record_type", record_type)
                
                try:
                    answers = await self.resolver.resolve(domain, record_type)
                    results = [rdata.to_text() for rdata in answers]
                    
                    op_logger.add_metric("results_count", len(results))
                    return results
                
                except dns.resolver.NoAnswer:
                    logger.debug(f"Sem resposta para {domain} {record_type}")
                    return []
                
                except dns.resolver.NXDOMAIN:
                    logger.debug(f"Domínio não existe: {domain}")
                    return []
                
                except dns.exception.Timeout as e:
                    raise DNSTimeoutError(
                        f"Timeout ao resolver {domain} {record_type}",
                        query_type=record_type,
                        domain=domain,
                        timeout=self.timeout,
                        original_error=e
                    )
                
                except dns.resolver.NoNameservers as e:
                    raise DNSResolutionError(
                        f"Nenhum nameserver respondeu para {domain}",
                        original_error=e
                    )
                
        except Exception as e:
            if isinstance(e, (DNSTimeoutError, DNSResolutionError)):
                raise
            
            # Converte exceções genéricas para exceções específicas do domínio
            if "network" in str(e).lower() or "connection" in str(e).lower():
                raise NetworkError(f"Erro de rede ao resolver {domain}: {e}", original_error=e)
            else:
                raise DNSResolutionError(f"Erro inesperado ao resolver {domain}: {e}", original_error=e)

    async def bulk_resolve_with_error_tracking(
        self,
        domains: List[Dict[str, str]],  # Lista de {"domain": "example.com", "type": "A"}
        workers: int = 20,
        rate_limiter: Optional[RateLimiter] = None
    ) -> Dict[str, Dict[str, List[str]]]:
        """
        Resolve múltiplos domínios com rastreamento de erros
        """
        semaphore = asyncio.Semaphore(workers)
        results = {}
        errors = []
        
        async def resolve_single(domain_info: Dict[str, str]):
            domain = domain_info["domain"]
            record_type = domain_info["type"]
            
            async with semaphore:
                if rate_limiter:
                    await rate_limiter.acquire()
                
                try:
                    result = await self.resolve_with_enhanced_error_handling(domain, record_type)
                    if result:
                        return {domain: {record_type: result}}
                except DNSTimeoutError as e:
                    errors.append({
                        "domain": domain,
                        "type": record_type,
                        "error": "timeout",
                        "message": str(e)
                    })
                    if rate_limiter:
                        rate_limiter.report_error()
                except DNSResolutionError as e:
                    errors.append({
                        "domain": domain,
                        "type": record_type,
                        "error": "resolution",
                        "message": str(e)
                    })
                    if rate_limiter:
                        rate_limiter.report_error()
                except Exception as e:
                    errors.append({
                        "domain": domain,
                        "type": record_type,
                        "error": "unexpected",
                        "message": str(e)
                    })
                    if rate_limiter:
                        rate_limiter.report_error()
                
                return {}
        
        tasks = [resolve_single(domain_info) for domain_info in domains]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Processa resultados e exceções não capturadas
        for result in batch_results:
            if isinstance(result, dict):
                results.update(result)
            elif isinstance(result, Exception):
                logger.error(f"Exceção não capturada: {result}")
        
        # Log de resumo de erros
        if errors:
            error_summary = {
                "total_errors": len(errors),
                "timeout_errors": sum(1 for e in errors if e["error"] == "timeout"),
                "resolution_errors": sum(1 for e in errors if e["error"] == "resolution"),
                "unexpected_errors": sum(1 for e in errors if e["error"] == "unexpected")
            }
            
            logger.warning(
                f"Resumo de erros durante bulk resolve: {error_summary}",
                extra={"extra_data": {"errors": errors}}
            )
        
        return results

# Função auxiliar para migração gradual
def create_enhanced_resolver(nameservers: Optional[List[str]] = None, timeout: float = 5.0) -> EnhancedDNSResolver:
    """
    Factory function para criar um resolver aprimorado
    """
    return EnhancedDNSResolver(nameservers, timeout)