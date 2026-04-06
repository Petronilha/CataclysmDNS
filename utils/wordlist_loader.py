import os

def load_wordlist(path: str) -> list[str]:
    """
    Carrega a wordlist de forma extremamente rápida.
    Usa 'errors=ignore' na raiz do CPython para pular bytes corrompidos
    sem gerar exceções de codec e sem perder tempo processando lixo.
    """
    if not os.path.exists(path):
        return []
        
    try:
        # Abertura cega e de alta performance. Pula qualquer caractere que não entende.
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []