import asyncio
import json
import time
from pathlib import Path

import aiohttp
import dns.asyncresolver
import dns.resolver
from rich.console import Console

console = Console()

class TakeoverDetector:
    """
    Módulo para detectar Subdomain Takeovers utilizando assinaturas dinâmicas
    da comunidade (can-i-take-over-xyz).
    """
    FINGERPRINTS_URL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
    CACHE_DIR = Path.home() / ".cataclysmdns"
    CACHE_FILE = CACHE_DIR / "fingerprints.json"
    CACHE_EXPIRY_DAYS = 7

    def __init__(self, concurrency: int = 50):
        self.concurrency = concurrency
        self.fingerprints: list[dict] = []
        # Utilizando o resolver assíncrono para máxima performance
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3

    async def initialize(self) -> None:
        """Baixa e carrega o banco de dados de fingerprints mais recente."""
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        needs_download = True

        if self.CACHE_FILE.exists():
            file_age_days = (time.time() - self.CACHE_FILE.stat().st_mtime) / 86400
            if file_age_days < self.CACHE_EXPIRY_DAYS:
                needs_download = False

        if needs_download:
            console.print("[cyan][*] Atualizando banco de dados de Subdomain Takeovers (can-i-take-over-xyz)...[/cyan]")
            await self._download_fingerprints()

        self._load_fingerprints()

    async def _download_fingerprints(self) -> None:
        """Busca o JSON oficial da comunidade."""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.FINGERPRINTS_URL, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json(content_type=None)
                        with open(self.CACHE_FILE, "w", encoding="utf-8") as f:
                            json.dump(data, f, indent=4)
                    else:
                        console.print(f"[red][!] Falha HTTP {response.status} ao baixar fingerprints.[/red]")
            except Exception as e:
                console.print(f"[red][!] Erro de rede ao buscar assinaturas: {e}[/red]")

    def _load_fingerprints(self) -> None:
        """Carrega os fingerprints do cache local para a memória."""
        try:
            with open(self.CACHE_FILE, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
                # Filtramos apenas os serviços oficialmente marcados como vulneráveis
                self.fingerprints = [entry for entry in raw_data if entry.get("status") == "Vulnerable"]
        except Exception:
            console.print("[yellow][!] Aviso: Arquivo de fingerprints ausente ou corrompido.[/yellow]")
            self.fingerprints = []

    async def check_subdomain(self, subdomain: str, session: aiohttp.ClientSession) -> dict | None:
            """
            Inspeciona um único subdomínio cruzando dados de DNS e requisição HTTP
            com o banco de assinaturas.
            """
            cname_records = []
            try:
                answers = await self.resolver.resolve(subdomain, 'CNAME')
                cname_records = [str(rdata.target).rstrip('.') for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass # Subdomínios sem CNAME podem pular essa etapa
            except Exception:
                return None

            for signature in self.fingerprints:
                service_cnames = signature.get("cname", [])
                matched_cname = False
                
                # Filtro 1: O CNAME do alvo bate com o provedor em nuvem?
                if cname_records and service_cnames:
                    for target_cname in cname_records:
                        if any(sc in target_cname for sc in service_cnames):
                            matched_cname = True
                            break

                # A MÁGICA ESTÁ AQUI: Exceção para Amazon S3 devido aos Alias Records da AWS
                is_s3 = signature.get("service") == "Amazon S3"

                # Se o CNAME bater, se a assinatura não exigir CNAME, OU se for Amazon S3, testamos a vulnerabilidade
                if matched_cname or not service_cnames or is_s3:
                    
                    # Filtro 2: Lógica de NXDOMAIN (O provedor exige que o CNAME não resolva para nada)
                    if signature.get("nxdomain", False):
                        try:
                            await self.resolver.resolve(subdomain, 'A')
                        except dns.resolver.NXDOMAIN:
                            return {"subdomain": subdomain, "service": signature["service"], "type": "NXDOMAIN (Dangling DNS)"}
                        except Exception:
                            pass
                    
                    # Filtro 3: Lógica de Fingerprint HTTP (O provedor exibe uma mensagem de erro específica)
                    expected_string = signature.get("fingerprint")
                    if expected_string:
                        try:
                            # Forçando timeout um pouco maior e tentando HTTP (o mais comum para takeovers S3)
                            url = f"http://{subdomain}"
                            async with session.get(url, timeout=10, ssl=False, allow_redirects=True) as resp:
                                body = await resp.text()
                                if expected_string in body:
                                    return {"subdomain": subdomain, "service": signature["service"], "type": "HTTP Fingerprint Match"}
                        except Exception:
                            pass
                            
            return None

    async def scan_list(self, subdomains: list[str]) -> list[dict]:
        """Coordena o escaneamento em massa de uma lista de subdomínios."""
        if not self.fingerprints:
            await self.initialize()

        results = []
        connector = aiohttp.TCPConnector(limit=self.concurrency)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.check_subdomain(sub, session) for sub in subdomains]
            
            # Executa com uma barra de progresso simples ou de forma silenciosa
            for future in asyncio.as_completed(tasks):
                result = await future
                if result:
                    console.print(f"[bold red][VULNERÁVEL][/bold red] {result['subdomain']} -> {result['service']} ({result['type']})")
                    results.append(result)
                    
        return results