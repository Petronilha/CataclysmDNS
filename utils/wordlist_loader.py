from pathlib import Path

def load_wordlist(path: str) -> list[str]:
    """
    Carrega a wordlist tentando diferentes codificações para evitar erros de codec.
    """
    # Lista de codificações para tentar, da mais comum para a mais compatível
    encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
    
    for enc in encodings:
        try:
            with open(path, 'r', encoding=enc) as f:
                # Se conseguir ler, retorna a lista
                return [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError:
            # Se der erro de codec, tenta a próxima codificação da lista
            continue
        except Exception as e:
            print(f"[bold red][!] Erro inesperado ao ler {path}:[/bold red] {e}")
            return []
            
    print(f"[bold red][!] Erro:[/bold red] Não foi possível decodificar a wordlist {path}.")
    return []