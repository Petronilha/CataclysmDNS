from pathlib import Path
import time
import os

def clean_old_logs(days: int = 7):
    """
    Remove arquivos de log mais antigos que o número especificado de dias
    """
    log_dir = Path("logs")
    if not log_dir.exists():
        return
    
    current_time = time.time()
    cutoff_time = current_time - (days * 24 * 60 * 60)
    
    for log_file in log_dir.glob("*.log*"):
        if log_file.is_file():
            file_modified_time = os.path.getmtime(log_file)
            if file_modified_time < cutoff_time:
                try:
                    log_file.unlink()
                    print(f"Removido log antigo: {log_file}")
                except Exception as e:
                    print(f"Erro ao remover {log_file}: {e}")

# Função para ser chamada no início da execução
def setup_log_cleaning():
    """
    Configura a limpeza automática de logs
    """
    import atexit
    atexit.register(clean_old_logs, days=7)