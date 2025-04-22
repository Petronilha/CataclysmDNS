from pathlib import Path

def load_wordlist(path: str) -> list[str]:
    """
    Lê um arquivo de wordlist, removendo linhas em branco e comentários.
    """
    words = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(line)
    return words