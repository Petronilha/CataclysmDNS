from pathlib import Path

def load_wordlist(path: str) -> list[str]:
    """
    Carrega a wordlist tratando erros de codificação (acentos, etc)
    """
    try:
        # Tenta ler como UTF-8 (padrão moderno)
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except UnicodeDecodeError:
        # Se falhar, tenta ler como latin-1 (ISO-8859-1), que aceita acentos brasileiros
        try:
            with open(path, 'r', encoding='latin-1') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[bold red][!] Erro ao ler wordlist:[/bold red] {e}")
            return []