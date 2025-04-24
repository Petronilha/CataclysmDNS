import sys
import logging
from .enhanced_logger import setup_enhanced_logger

def get_logger(name: str):
    """
    Retorna um logger configurado baseado no modo de execução
    """
    # Verifica se está em modo debug
    is_debug = "--debug" in sys.argv
    is_verbose = "--verbose" in sys.argv or "-v" in sys.argv
    
    # Configura o logger
    logger = setup_enhanced_logger(
        name,
        level="DEBUG",  # Sempre coleta todos os níveis de log
        json_file=f"logs/{name}.log",
        verbose=is_verbose,
        console_output=is_debug  # Só mostra no console se estiver em modo debug
    )
    
    # Se não estiver em modo debug, configura para não mostrar níveis DEBUG no console
    if not is_debug:
        # Filtra mensagens de DEBUG para que não apareçam no console
        class DebugFilter(logging.Filter):
            def filter(self, record):
                return record.levelno > logging.DEBUG
        
        # Aplica o filtro em todos os handlers de console
        for handler in logger.handlers:
            if hasattr(handler, 'console') or isinstance(handler, logging.StreamHandler):
                handler.addFilter(DebugFilter())
    
    return logger

# Função para desabilitar completamente o output no console para um logger específico
def disable_console_logging(logger):
    """Remove todos os handlers de console de um logger"""
    for handler in logger.handlers[:]:
        if hasattr(handler, 'console'):
            logger.removeHandler(handler)

# Desabilita o logger raiz para evitar propagação
logging.getLogger().handlers = []
logging.getLogger().addHandler(logging.NullHandler())