import socks
import socket
import time
import random
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
import requests
from urllib.parse import urlparse
from utils.logger import setup_logger

logger = setup_logger("proxy_manager")

@dataclass
class ProxyConfig:
    host: str
    port: int
    proxy_type: str = "socks5"
    username: Optional[str] = None
    password: Optional[str] = None

class ProxyManager:
    """Gerenciador de proxies com suporte a SOCKS5 e HTTP"""
    
    def __init__(self):
        self.proxies: List[ProxyConfig] = []
        self.current_index = 0
        self.enabled = False
        self.original_socket = None
        self.original_getaddrinfo = None
    
    def add_proxy(self, proxy_url: str):
        """Adiciona um proxy à lista (socks5://user:pass@host:port)"""
        try:
            parsed = urlparse(proxy_url)
            proxy = ProxyConfig(
                host=parsed.hostname or "127.0.0.1",
                port=parsed.port or 9050,
                proxy_type=parsed.scheme or "socks5",
                username=parsed.username,
                password=parsed.password
            )
            self.proxies.append(proxy)
            logger.info(f"Proxy adicionado: {proxy.host}:{proxy.port}")
        except Exception as e:
            logger.error(f"Erro ao adicionar proxy: {e}")
    
    def get_next_proxy(self) -> Optional[ProxyConfig]:
        """Retorna o próximo proxy na rotação"""
        if not self.proxies:
            return None
        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        return proxy
    
    def test_tor_connection(self, proxy: ProxyConfig) -> bool:
        """Testa se o Tor está funcionando"""
        try:
            # Teste básico de socket primeiro
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            test_socket.connect((proxy.host, proxy.port))
            test_socket.close()
            logger.info(f"✓ Socket conectado a {proxy.host}:{proxy.port}")
            
            # Agora testa com requests usando socks5h (resolve DNS pelo proxy)
            proxies = {
                'http': f'socks5h://{proxy.host}:{proxy.port}',
                'https': f'socks5h://{proxy.host}:{proxy.port}'
            }
            
            # Usa um site confiável para teste
            try:
                response = requests.get('https://check.torproject.org/api/ip', 
                                      proxies=proxies, 
                                      timeout=10)
                
                data = response.json()
                if data.get('IsTor', False):
                    logger.info(f"✓ Tor está funcionando! IP: {data.get('IP')}")
                    return True
                else:
                    logger.error("✗ Não está usando Tor")
                    return False
            except requests.exceptions.RequestException as e:
                logger.warning(f"Falha no teste Tor, tentando alternativa: {e}")
                # Tenta um site alternativo
                try:
                    response = requests.get('https://ipinfo.io/json', 
                                          proxies=proxies, 
                                          timeout=10)
                    if response.status_code == 200:
                        logger.info(f"✓ Proxy funcionando com IP: {response.json().get('ip')}")
                        return True
                except:
                    pass
                    
            return False
                
        except Exception as e:
            logger.error(f"✗ Erro ao testar conexão Tor: {e}")
            return False
    
    def setup_socket(self):
        """Configura o socket para usar o proxy atual"""
        if not self.enabled or not self.proxies:
            logger.warning("Proxy não habilitado ou lista vazia")
            return
        
        proxy = self.get_next_proxy()
        if proxy.proxy_type == "socks5":
            try:
                # Primeiro verifica se o Tor está rodando
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(5)
                try:
                    test_socket.connect((proxy.host, proxy.port))
                    test_socket.close()
                except Exception as e:
                    raise ConnectionError(f"Não foi possível conectar ao Tor: {e}")
                
                # Salva as funções originais
                self.original_socket = socket.socket
                self.original_getaddrinfo = socket.getaddrinfo
                
                # Configura o proxy sem testar ainda
                socks.set_default_proxy(
                    socks.SOCKS5, 
                    addr=proxy.host, 
                    port=proxy.port,
                    rdns=True,  # Força resolução DNS pelo proxy
                    username=proxy.username,
                    password=proxy.password
                )
                
                # Substitui o socket
                socket.socket = socks.socksocket
                
                # Função personalizada para getaddrinfo
                def proxy_getaddrinfo(*args, **kwargs):
                    # Força resolução de DNS pelo proxy
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]
                
                socket.getaddrinfo = proxy_getaddrinfo
                
                # Agora espera um pouco e testa a conexão
                time.sleep(1)
                
                if not self.test_tor_connection(proxy):
                    self.reset_socket()
                    raise ConnectionError("Não foi possível conectar ao Tor")
                
                logger.info(f"✓ Proxy SOCKS5 configurado: {proxy.host}:{proxy.port}")
                
            except Exception as e:
                logger.error(f"✗ Erro ao configurar proxy: {e}")
                self.reset_socket()
                raise
    
    def _proxy_getaddrinfo(self, *args, **kwargs):
        """Força a resolução pelo proxy"""
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]
    
    def reset_socket(self):
        """Reseta o socket para não usar proxy"""
        if self.original_socket:
            socket.socket = self.original_socket
        if self.original_getaddrinfo:
            socket.getaddrinfo = self.original_getaddrinfo
        logger.info("Socket resetado para configuração original")