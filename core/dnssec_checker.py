import dns.resolver
from rich.console import Console
from utils.logger import setup_logger

logger = setup_logger("dnssec")
console = Console()

def check_dnssec(domain: str) -> bool:
    """
    Verifica DNSSEC com output detalhado
    """
    console.print(f"[cyan]Verificando DNSSEC para {domain}...[/cyan]")
    console.print()  # Linha em branco
    
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        console.print(f"[green][+][/green] DNSKEY encontrado para {domain}")
        console.print(f"[blue]   Número de chaves: {len(answers)}[/blue]")
        
        for i, key in enumerate(answers, 1):
            console.print(f"[blue]   Chave {i}: Algoritmo {key.algorithm}, Flags {key.flags}[/blue]")
        
        # Tenta obter RRSIG para verificar assinaturas
        try:
            rrsig_answers = dns.resolver.resolve(domain, 'RRSIG')
            console.print(f"[green][+][/green] RRSIG encontrado - domínio está assinado")
        except:
            console.print(f"[yellow][!][/yellow] RRSIG não encontrado")
        
        return True
    except Exception as e:
        console.print(f"[red][-][/red] DNSSEC não está habilitado: {e}")
        return False