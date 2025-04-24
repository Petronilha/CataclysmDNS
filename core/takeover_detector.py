import dns.resolver
import aiohttp
import asyncio
from typing import Dict, Optional, List, Tuple
from utils.logger import setup_logger

logger = setup_logger("takeover_detector")

class SubdomainTakeoverDetector:
    """
    Detecta vulnerabilidades de subdomain takeover em diversos serviços cloud
    """
    
    def __init__(self):
        self.vulnerable_fingerprints = {
            # Serviço: (fingerprint, possível, mensagem)
            'github': {
                'cname': 'github.io',
                'fingerprint': 'There isn\'t a GitHub Pages site here.',
                'vulnerable': True,
                'message': 'GitHub Pages não configurado'
            },
            'heroku': {
                'cname': 'herokuapp.com',
                'fingerprint': 'No such app',
                'vulnerable': True,
                'message': 'Aplicação Heroku não encontrada'
            },
            'aws_s3': {
                'cname': ['s3.amazonaws.com', 's3-website'],
                'fingerprint': 'NoSuchBucket',
                'vulnerable': True,
                'message': 'S3 bucket não existe'
            },
            'azure': {
                'cname': 'azurewebsites.net',
                'fingerprint': ['Azure Web App - Error 404', 'Domain has not be properly configured'],
                'vulnerable': True,
                'message': 'Azure Web App não configurado'
            },
            'shopify': {
                'cname': 'myshopify.com',
                'fingerprint': 'Sorry, this shop is currently unavailable',
                'vulnerable': True,
                'message': 'Loja Shopify não configurada'
            },
            'zendesk': {
                'cname': 'zendesk.com',
                'fingerprint': 'Help Center Closed',
                'vulnerable': True,
                'message': 'Zendesk não configurado'
            },
            'wordpress': {
                'cname': 'wpengine.com',
                'fingerprint': 'This site is not available yet',
                'vulnerable': True,
                'message': 'WordPress não configurado'
            },
            'fastly': {
                'cname': 'fastly.net',
                'fingerprint': 'Fastly error: unknown domain',
                'vulnerable': True,
                'message': 'Fastly não configurado'
            },
            'netlify': {
                'cname': 'netlify.app',
                'fingerprint': 'Not Found',
                'vulnerable': True,
                'message': 'Netlify não configurado'
            },
            'ghost': {
                'cname': 'ghost.io',
                'fingerprint': ['404: Page not found', 'The thing you were looking for is no longer here'],
                'vulnerable': True,
                'message': 'Ghost blog não configurado'
            }
        }
        
        # Headers para evitar bloqueios
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    async def check_subdomain(self, subdomain: str) -> Dict:
        """
        Verifica se um subdomínio está vulnerável a takeover
        """
        try:
            # Primeiro, verificar se o subdomínio existe
            cname_record = self._get_cname_record(subdomain)
            
            if not cname_record:
                return {'vulnerable': False, 'reason': 'Sem registro CNAME'}
            
            # Verificar se o CNAME aponta para um serviço conhecido
            service_info = self._identify_service(cname_record)
            
            if not service_info:
                return {'vulnerable': False, 'reason': 'Serviço não reconhecido'}
            
            # Verificar se o serviço está vulnerável
            is_vulnerable = await self._check_vulnerability(subdomain, service_info)
            
            return {
                'subdomain': subdomain,
                'vulnerable': is_vulnerable,
                'service': service_info['service'],
                'cname': cname_record,
                'message': service_info['message'] if is_vulnerable else 'Não vulnerável',
                'recommendation': self._get_recommendation(service_info['service']) if is_vulnerable else None
            }
            
        except Exception as e:
            logger.error(f"Erro ao verificar {subdomain}: {e}")
            return {'vulnerable': False, 'error': str(e)}
    
    def _get_cname_record(self, subdomain: str) -> Optional[str]:
        """
        Obtém o registro CNAME do subdomínio
        """
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            return str(answers[0].target).rstrip('.')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # Tentar pegar registro A e verificar se é alias de algum serviço
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                # Verificar PTR para descobrir o serviço
                return None
            except:
                return None
        except Exception as e:
            logger.debug(f"Erro ao obter CNAME de {subdomain}: {e}")
            return None
    
    def _identify_service(self, cname: str) -> Optional[Dict]:
        """
        Identifica o serviço baseado no CNAME
        """
        for service, config in self.vulnerable_fingerprints.items():
            
            if isinstance(config['cname'], list):
                if any(cn in cname for cn in config['cname']):
                    return {'service': service, **config}
            else:
                if config['cname'] in cname:
                    return {'service': service, **config}
        
        return None
    
    async def _check_vulnerability(self, subdomain: str, service_info: Dict) -> bool:
        """
        Verifica se o serviço está vulnerável acessando o subdomínio
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{subdomain}"
                
                async with session.get(url, headers=self.headers, timeout=10) as response:
                    content = await response.text()
                    status = response.status
                    
                    # Verificar fingerprints
                    fingerprints = service_info['fingerprint']
                    if isinstance(fingerprints, list):
                        return any(fp in content for fp in fingerprints)
                    else:
                        return fingerprints in content
                    
        except aiohttp.ClientError as e:
            # Alguns erros de conexão também indicam vulnerabilidade
            if 'Cannot connect' in str(e) or 'Name or service not known' in str(e):
                return True
            logger.debug(f"Erro ao acessar {subdomain}: {e}")
            return False
        except Exception as e:
            logger.debug(f"Erro inesperado ao verificar {subdomain}: {e}")
            return False
    
    def _get_recommendation(self, service: str) -> str:
        """
        Retorna recomendações específicas por serviço
        """
        recommendations = {
            'github': 'Crie um repositório GitHub Pages com o nome correto ou remova o registro CNAME',
            'heroku': 'Crie uma aplicação Heroku com o nome correto ou remova o registro CNAME',
            'aws_s3': 'Crie o bucket S3 com o nome correto ou remova o registro CNAME',
            'azure': 'Configure o Azure Web App ou remova o registro CNAME',
            'shopify': 'Configure sua loja Shopify ou remova o registro CNAME',
            'zendesk': 'Configure seu Zendesk ou remova o registro CNAME',
            'wordpress': 'Configure seu site WordPress ou remova o registro CNAME',
            'fastly': 'Configure o serviço Fastly ou remova o registro CNAME',
            'netlify': 'Configure seu site Netlify ou remova o registro CNAME',
            'ghost': 'Configure seu blog Ghost ou remova o registro CNAME'
        }
        
        return recommendations.get(service, 'Remova o registro CNAME ou configure o serviço corretamente')
    
    async def scan_subdomains(self, subdomains: List[str], workers: int = 10) -> List[Dict]:
        """
        Escaneia múltiplos subdomínios em paralelo
        """
        semaphore = asyncio.Semaphore(workers)
        
        async def check_with_semaphore(subdomain):
            async with semaphore:
                return await self.check_subdomain(subdomain)
        
        tasks = [check_with_semaphore(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks)
        
        # Filtrar apenas vulneráveis
        vulnerable_results = [r for r in results if r.get('vulnerable', False)]
        
        return vulnerable_results