import socks
import socket
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
        self.original_socket = socket.socket
    
    def add_proxy(self, proxy_url: str):
        """Adiciona um proxy à lista (socks5://user:pass@host:port)"""
        try:
            parsed = urlparse(proxy_url)
            proxy = ProxyConfig(
                host=parsed.hostname,
                port=parsed.port,
                proxy_type=parsed.scheme,
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
    
    def setup_socket(self):
      """Configura o socket para usar o proxy atual"""
      if not self.enabled or not self.proxies:
          logger.warning("Proxy não habilitado ou lista vazia")
          return
      
      proxy = self.get_next_proxy()
      if proxy.proxy_type == "socks5":
          try:
              socks.set_default_proxy(
                  socks.SOCKS5, 
                  proxy.host, 
                  proxy.port,
                  username=proxy.username,
                  password=proxy.password,
                  rdns=True
              )
              socket.socket = socks.socksocket
              logger.info(f"✓ Proxy SOCKS5 configurado: {proxy.host}:{proxy.port}")
              
              # Teste de conexão
              test_socket = socket.socket()
              test_socket.connect(("127.0.0.1", proxy.port))
              test_socket.close()
              logger.info("✓ Teste de conexão bem-sucedido")
          except Exception as e:
              logger.error(f"✗ Erro ao configurar proxy: {e}")
              raise
    
    def reset_socket(self):
        """Reseta o socket para não usar proxy"""
        socket.socket = self.original_socket