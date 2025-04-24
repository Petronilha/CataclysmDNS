# config.py
import os
from dotenv import load_dotenv
from pathlib import Path

class Config:
    def __init__(self):
        # Carrega variáveis do .env
        env_path = Path('.env')
        if env_path.exists():
            load_dotenv(env_path)
        
        # API Keys
        self.VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
        self.URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY')
        self.DNSDUMPSTER_API_KEY = os.getenv('DNSDUMPSTER_API_KEY')
        self.ALIENVAULT_API_KEY = os.getenv('ALIENVAULT_API_KEY')
        
        # Configurações de timeout e retry
        self.TIMEOUT = int(os.getenv('TIMEOUT', '30'))
        self.MAX_RETRIES = int(os.getenv('MAX_RETRIES', '3'))

config = Config()