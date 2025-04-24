from typing import List

class CachedDNSResolver:
    """
    Versão simplificada do resolver com cache para evitar importações circulares
    """
    def __init__(self, nameservers=None, timeout=5.0):
        self.nameservers = nameservers
        self.timeout = timeout
    
    async def resolve_with_enhanced_error_handling(
        self,
        domain: str,
        record_type: str
    ) -> List[str]:
        """
        Versão sem cache para evitar problemas de importação
        """
        from .resolver_enhanced import EnhancedDNSResolver
        
        resolver = EnhancedDNSResolver(self.nameservers, self.timeout)
        return await resolver.resolve_with_enhanced_error_handling(domain, record_type)
    
    async def bulk_resolve_with_error_tracking(
        self,
        domains,
        workers=20,
        rate_limiter=None
    ):
        """
        Versão sem cache para evitar problemas de importação
        """
        from .resolver_enhanced import EnhancedDNSResolver
        
        resolver = EnhancedDNSResolver(self.nameservers, self.timeout)
        return await resolver.bulk_resolve_with_error_tracking(domains, workers, rate_limiter)

# Função auxiliar para migração gradual
def create_cached_resolver(nameservers=None, timeout=5.0):
    """
    Factory function para criar um resolver com cache
    """
    return CachedDNSResolver(nameservers, timeout)