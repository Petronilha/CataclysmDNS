import aiohttp
import asyncio
import json
import re
from typing import Set, Dict, List, Optional
from datetime import datetime
import ssl
import certifi
from bs4 import BeautifulSoup
from rich.console import Console
from utils.logger import setup_logger
from config import config

logger = setup_logger("passive_recon")
console = Console()

class PassiveRecon:
    """
    Realiza reconhecimento passivo de DNS utilizando múltiplas fontes de dados
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
    
    async def search_crtsh(self, domain: str) -> Set[str]:
        """
        Busca em Certificate Transparency logs via crt.sh
        """
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers, timeout=self.timeout, ssl=self.ssl_context) as response:
                    if response.status == 200:
                        data = await response.json()
                        subdomains = set()
                        
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            if name_value:
                                # Extrair todos os domínios do certificado
                                names = name_value.split('\n')
                                for name in names:
                                    if name.endswith(domain) and not name.startswith('*'):
                                        subdomains.add(name.lower())
                        
                        # Mostra apenas o resumo
                        count = len(subdomains)
                        if count > 0:
                            console.print(f"[green][+][/green] [crt.sh] {count} subdomínios encontrados")
                        else:
                            console.print(f"[yellow][-][/yellow] [crt.sh] Nenhum subdomínio encontrado")
                        
                        return subdomains
        except Exception as e:
            logger.error(f"Erro ao consultar crt.sh: {e}")
            console.print(f"[red][!][/red] [crt.sh] Erro ao consultar")
        
        return set()
    
    async def search_hackertarget(self, domain: str) -> Set[str]:
        """
        Busca usando a API do HackerTarget
        """
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers, timeout=self.timeout) as response:
                    if response.status == 200:
                        text = await response.text()
                        subdomains = set()
                        
                        for line in text.split('\n'):
                            if ',' in line:
                                subdomain = line.split(',')[0]
                                if subdomain.endswith(domain):
                                    subdomains.add(subdomain.lower())
                        
                        # Mostra apenas o resumo
                        count = len(subdomains)
                        if count > 0:
                            console.print(f"[green][+][/green] [HackerTarget] {count} subdomínios encontrados")
                        else:
                            console.print(f"[yellow][-][/yellow] [HackerTarget] Nenhum subdomínio encontrado")
                        
                        return subdomains
        except Exception as e:
            logger.error(f"Erro ao consultar HackerTarget: {e}")
            console.print(f"[red][!][/red] [HackerTarget] Erro ao consultar")
        
        return set()
    
    async def search_alienvault(self, domain: str) -> Set[str]:
        """
        Busca usando AlienVault OTX
        """
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            
            response_text, status = await self._make_request(url)
            
            if response_text and status == 200:
                data = json.loads(response_text)
                subdomains = set()
                
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '')
                    if hostname.endswith(domain):
                        subdomains.add(hostname.lower())
                
                # Mostra apenas o resumo
                count = len(subdomains)
                if count > 0:
                    console.print(f"[green][+][/green] [AlienVault] {count} subdomínios encontrados")
                else:
                    console.print(f"[yellow][-][/yellow] [AlienVault] Nenhum subdomínio encontrado")
                
                return subdomains
        except Exception as e:
            logger.error(f"Erro ao consultar AlienVault: {e}")
            console.print(f"[red][!][/red] [AlienVault] Erro ao consultar")
        
        return set()
    
    async def search_virustotal(self, domain: str, api_key: Optional[str] = None) -> Set[str]:
        """
        Busca usando VirusTotal
        """
        api_key = api_key or config.VIRUSTOTAL_API_KEY
        
        if not api_key:
            logger.info("[VirusTotal] Pulando - API key não fornecida")
            console.print(f"[yellow][-][/yellow] [VirusTotal] API key não fornecida")
            return set()
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {
                **self.headers,
                'x-apikey': api_key
            }
            
            response_text, status = await self._make_request(url, headers=headers)
            
            if response_text and status == 200:
                data = json.loads(response_text)
                subdomains = set()
                
                for item in data.get('data', []):
                    subdomain = item.get('id', '')
                    if subdomain.endswith(domain):
                        subdomains.add(subdomain.lower())
                
                # Mostra apenas o resumo
                count = len(subdomains)
                if count > 0:
                    console.print(f"[green][+][/green] [VirusTotal] {count} subdomínios encontrados")
                else:
                    console.print(f"[yellow][-][/yellow] [VirusTotal] Nenhum subdomínio encontrado")
                
                return subdomains
        except Exception as e:
            logger.error(f"Erro ao consultar VirusTotal: {e}")
            console.print(f"[red][!][/red] [VirusTotal] Erro ao consultar")
        
        return set()
    
    async def search_wayback(self, domain: str) -> Set[str]:
        """
        Busca usando Wayback Machine
        """
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers, timeout=self.timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        subdomains = set()
                        
                        for entry in data[1:]:  # Pula o header
                            if entry:
                                url = entry[0]
                                # Extrair subdomínio do URL
                                match = re.search(r'https?://([^/]+)', url)
                                if match:
                                    subdomain = match.group(1)
                                    if subdomain.endswith(domain):
                                        subdomains.add(subdomain.lower())
                        
                        # Mostra apenas o resumo
                        count = len(subdomains)
                        if count > 0:
                            console.print(f"[green][+][/green] [Wayback] {count} subdomínios encontrados")
                        else:
                            console.print(f"[yellow][-][/yellow] [Wayback] Nenhum subdomínio encontrado")
                        
                        return subdomains
        except Exception as e:
            logger.error(f"Erro ao consultar Wayback: {e}")
            console.print(f"[red][!][/red] [Wayback] Erro ao consultar")
        
        return set()
    
    async def search_urlscan(self, domain: str) -> Set[str]:
        """
        Busca usando URLScan.io
        """
        api_key = self.api_configs.get('urlscan', {}).get('key')
        
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
            headers = {**self.headers}
            
            if api_key:
                headers['API-Key'] = api_key
            
            response_text, status = await self._make_request(url, headers=headers)
            
            if response_text and status == 200:
                data = json.loads(response_text)
                subdomains = set()
                
                for result in data.get('results', []):
                    page = result.get('page', {})
                    subdomain = page.get('domain', '')
                    if subdomain.endswith(domain):
                        subdomains.add(subdomain.lower())
                
                # Mostra apenas o resumo
                count = len(subdomains)
                if count > 0:
                    console.print(f"[green][+][/green] [URLScan] {count} subdomínios encontrados")
                else:
                    console.print(f"[yellow][-][/yellow] [URLScan] Nenhum subdomínio encontrado")
                
                return subdomains
        except Exception as e:
            logger.error(f"Erro ao consultar URLScan: {e}")
            console.print(f"[red][!][/red] [URLScan] Erro ao consultar")
        
        return set()
    
    async def search_dnsdumpster(self, domain: str) -> Set[str]:
        """
        Busca usando DNS Dumpster
        """
        try:
            url = "https://dnsdumpster.com/"
            
            async with aiohttp.ClientSession() as session:
                # Primeiro, obter CSRF token
                async with session.get(url, headers=self.headers) as response:
                    if response.status != 200:
                        return set()
                    
                    html = await response.text()
                    csrf_match = re.search(r'csrf_token.*?value="(.*?)"', html)
                    if not csrf_match:
                        return set()
                    
                    csrf_token = csrf_match.group(1)
                
                # Fazer a pesquisa
                data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'targetip': domain
                }
                
                async with session.post(url, data=data, headers=self.headers) as response:
                    if response.status == 200:
                        html = await response.text()
                        subdomains = set()
                        
                        # Extrair subdomínios do HTML
                        pattern = re.compile(r'([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + ')')
                        matches = pattern.findall(html)
                        
                        for match in matches:
                            if not match.startswith('*'):
                                subdomains.add(match.lower())
                        
                        # Mostra apenas o resumo
                        count = len(subdomains)
                        if count > 0:
                            console.print(f"[green][+][/green] [DNSDumpster] {count} subdomínios encontrados")
                        else:
                            console.print(f"[yellow][-][/yellow] [DNSDumpster] Nenhum subdomínio encontrado")
                        
                        return subdomains
        except Exception as e:
            logger.error(f"Erro ao consultar DNSDumpster: {e}")
            console.print(f"[red][!][/red] [DNSDumpster] Erro ao consultar")
        
        return set()
    
    async def gather_subdomains(self, domain: str) -> Dict:
        """
        Executa todas as buscas de forma assíncrona com output em tempo real
        """
        console.print(f"[cyan]Iniciando reconhecimento passivo para {domain}[/cyan]")
        console.print()  # Linha em branco
        
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
        
        console.print()  # Linha em branco antes do resumo
        console.print(f"[bold cyan]Resumo do reconhecimento passivo:[/]")
        
        stats = {
            'total_subdomains': len(all_subdomains),
            'sources': source_counts,
            'timestamp': datetime.now().isoformat(),
        }
        
        return {
            'subdomains': sorted(list(all_subdomains)),
            'stats': stats
        }