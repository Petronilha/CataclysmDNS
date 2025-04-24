import aiohttp
import asyncio
import json
from typing import Set, Dict, List, Optional
from datetime import datetime
import ssl
import certifi
from bs4 import BeautifulSoup
from utils.logger import setup_enhanced_logger
from config import config
from core.cache_config import get_passive_cache, get_api_cache
from core.cache_manager import cached

logger = setup_enhanced_logger("passive_recon")
passive_cache = get_passive_cache()
api_cache = get_api_cache()

class PassiveRecon:
    """
    Realiza reconhecimento passivo de DNS utilizando múltiplas fontes de dados com cache
    """
    
    def __init__(self, timeout: int = None, debug: bool = False):
        self.timeout = timeout or config.TIMEOUT
        self.results = set()
        self.metadata = {}
        self.debug = debug
        
        # Headers para evitar detecção
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        
        self.api_configs = {
            'virustotal': {'key': config.VIRUSTOTAL_API_KEY, 'required': True},
            'urlscan': {'key': config.URLSCAN_API_KEY, 'required': False},
            'dnsdumpster': {'key': config.DNSDUMPSTER_API_KEY, 'required': True},
            'alienvault': {'key': config.ALIENVAULT_API_KEY, 'required': False},
        }
        
        # Configuração SSL
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        
        # Configuração SSL para sites com problemas
        self.insecure_ssl_context = ssl.create_default_context()
        self.insecure_ssl_context.check_hostname = False
        self.insecure_ssl_context.verify_mode = ssl.CERT_NONE
    
    async def _cached_request(self, url: str, headers: dict = None, ssl_context=None, method='GET', data=None, cache_ttl=3600):
        """
        Requisição HTTP com cache
        """
        cache_key = f"{method}:{url}:{str(headers)}:{str(data)}"
        cached_response = await api_cache.get(cache_key, namespace="http_requests")
        
        if cached_response is not None:
            logger.debug(f"Cache hit para requisição HTTP: {url}")
            return cached_response[0], cached_response[1]
        
        response_text, status = await self._make_request(url, headers, ssl_context, method, data)
        
        if response_text and status == 200:
            await api_cache.set(
                cache_key,
                (response_text, status),
                namespace="http_requests",
                ttl=cache_ttl
            )
        
        return response_text, status
    
    async def _make_request(self, url: str, headers: dict = None, ssl_context=None, method='GET', data=None):
        """
        Função genérica para fazer requisições com tratamento de erro
        """
        headers = headers or self.headers
        ssl_context = ssl_context or self.ssl_context
        
        try:
            async with aiohttp.ClientSession() as session:
                if method == 'GET':
                    async with session.get(url, headers=headers, timeout=self.timeout, ssl=ssl_context) as response:
                        return await response.text(), response.status
                elif method == 'POST':
                    async with session.post(url, headers=headers, data=data, timeout=self.timeout, ssl=ssl_context) as response:
                        return await response.text(), response.status
        except aiohttp.ClientConnectorError as e:
            logger.error(f"Falha de conexão para {url}: {e}")
            return None, None
        except asyncio.TimeoutError:
            logger.error(f"Timeout na requisição para {url}")
            return None, None
        except Exception as e:
            logger.error(f"Erro na requisição para {url}: {e}")
            return None, None
    
    async def search_virustotal(self, domain: str, api_key: Optional[str] = None) -> Set[str]:
        """
        Busca usando VirusTotal com cache
        """
        cache_key = f"virustotal:{domain}"
        cached_result = await passive_cache.get(cache_key, namespace="virustotal")
        
        if cached_result is not None:
            logger.debug(f"Cache hit para VirusTotal: {domain}")
            return set(cached_result)
        
        # Usa a API key do config se não for fornecida
        api_key = api_key or config.VIRUSTOTAL_API_KEY
        
        if not api_key:
            logger.info("[VirusTotal] Pulando - API key não fornecida")
            return set()
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {
                **self.headers,
                'x-apikey': api_key
            }
            
            response_text, status = await self._cached_request(url, headers=headers, cache_ttl=7200)
            
            if response_text and status == 200:
                data = json.loads(response_text)
                subdomains = set()
                
                for item in data.get('data', []):
                    subdomain = item.get('id', '')
                    if subdomain.endswith(domain):
                        subdomains.add(subdomain.lower())
                
                logger.info(f"[VirusTotal] Encontrados {len(subdomains)} subdomínios")
                
                # Armazenar no cache
                await passive_cache.set(
                    cache_key,
                    list(subdomains),
                    namespace="virustotal",
                    ttl=86400  # 24 horas
                )
                
                return subdomains
        except Exception as e:
            logger.error(f"Erro ao consultar VirusTotal: {e}")
        
        return set()
    
    async def search_crtsh(self, domain: str) -> Set[str]:
        """
        Busca em Certificate Transparency logs via crt.sh com cache
        """
        cache_key = f"crtsh:{domain}"
        cached_result = await passive_cache.get(cache_key, namespace="crtsh")
        
        if cached_result is not None:
            logger.debug(f"Cache hit para crt.sh: {domain}")
            return set(cached_result)
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            response_text, status = await self._cached_request(url, cache_ttl=3600)
            
            if response_text and status == 200:
                data = json.loads(response_text)
                subdomains = set()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        # Extrair todos os domínios do certificado
                        names = name_value.split('\n')
                        for name in names:
                            if name.endswith(domain) and not name.startswith('*'):
                                subdomains.add(name.lower())
                
                logger.info(f"[crt.sh] Encontrados {len(subdomains)} subdomínios")
                
                # Armazenar no cache
                await passive_cache.set(
                    cache_key,
                    list(subdomains),
                    namespace="crtsh",
                    ttl=86400  # 24 horas
                )
                
                return subdomains
        except Exception as e:
            logger.error(f"Erro ao consultar crt.sh: {e}")
        
        return set()
    
    async def gather_subdomains(self, domain: str) -> Dict:
        """
        Executa todas as buscas de forma assíncrona com cache
        """
        # Verificar cache geral primeiro
        general_cache_key = f"passive_recon:{domain}"
        cached_result = await passive_cache.get(general_cache_key, namespace="general")
        
        if cached_result is not None:
            logger.info(f"Cache hit para reconhecimento passivo geral: {domain}")
            return cached_result
        
        logger.info(f"Iniciando reconhecimento passivo para {domain}")
        
        # Executa todas as buscas em paralelo
        tasks = [
            self.search_crtsh(domain),
            self.search_hackertarget(domain),
            self.search_alienvault(domain),
            self.search_urlscan(domain),
            self.search_wayback(domain),
            self.search_virustotal(domain),
            self.search_dnsdumpster(domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combina todos os resultados
        all_subdomains = set()
        source_counts = {}
        
        sources = [
            'crt.sh', 'HackerTarget', 'AlienVault', 'URLScan', 
            'Wayback', 'VirusTotal', 'DNSDumpster'
        ]
        
        for source, result in zip(sources, results):
            if isinstance(result, set):
                all_subdomains.update(result)
                source_counts[source] = len(result)
            else:
                if isinstance(result, Exception):
                    logger.error(f"Exceção em {source}: {result}")
                elif result is None:
                    logger.warning(f"Sem resultados de {source}")
                source_counts[source] = 0
        
        # Gera estatísticas
        stats = {
            'total_subdomains': len(all_subdomains),
            'sources': source_counts,
            'timestamp': datetime.now().isoformat(),
        }
        
        result = {
            'subdomains': sorted(list(all_subdomains)),
            'stats': stats
        }
        
        # Armazenar no cache geral
        await passive_cache.set(
            general_cache_key,
            result,
            namespace="general",
            ttl=86400  # 24 horas
        )
        
        return result