from rich.logging import RichHandler
from rich.console import Console
import logging
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

class EnhancedLogger:
    """Logger aprimorado com suporte a logging estruturado e diferentes níveis de verbosidade"""
    
    def __init__(
        self,
        name: str,
        level: str = "INFO",
        json_file: Optional[str] = None,
        verbose: bool = False,
        console_output: bool = False  # Novo parâmetro para controlar saída no console
    ):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # IMPORTANTE: Desabilita propagação para evitar que logs apareçam em handlers pais
        self.logger.propagate = False
        
        # Remove handlers existentes para evitar duplicação
        self.logger.handlers.clear()
        
        # Console handler com Rich (somente se console_output for True)
        if console_output:
            console_handler = RichHandler(
                console=Console(stderr=True),
                show_time=True,
                show_path=verbose,
                rich_tracebacks=True,
                tracebacks_show_locals=verbose,
                markup=True
            )
            console_handler.setFormatter(
                logging.Formatter("%(message)s", datefmt="[%X]")
            )
            self.logger.addHandler(console_handler)
        
        # File handler com rotação por tamanho
        if json_file:
            # Garante que o diretório existe
            log_dir = Path(json_file).parent
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Usar TimedRotatingFileHandler para rotação diária
            timed_handler = TimedRotatingFileHandler(
                json_file,
                when='midnight',  # Rotação diária
                interval=1,
                backupCount=7,  # Mantém logs dos últimos 7 dias
                encoding='utf-8'
            )
            timed_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            )
            self.logger.addHandler(timed_handler)
            
            # Adiciona também um handler com rotação por tamanho para evitar arquivos muito grandes
            size_handler = RotatingFileHandler(
                f"{json_file}.size",
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5,  # Mantém até 5 arquivos de backup
                encoding='utf-8'
            )
            size_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            )
            self.logger.addHandler(size_handler)
        
        # Se nenhum handler foi adicionado, adiciona um NullHandler para evitar warnings
        if not self.logger.handlers:
            self.logger.addHandler(logging.NullHandler())
    
    def get_logger(self) -> logging.Logger:
        return self.logger

class JSONFileHandler(logging.Handler):
    """Handler para salvar logs em formato JSON"""
    
    def __init__(self, filename: str):
        super().__init__()
        self.filename = filename
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
    
    def emit(self, record: logging.LogRecord):
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Adiciona informações extras se disponíveis
        if hasattr(record, "extra_data"):
            log_entry["extra"] = record.extra_data
        
        # Adiciona stack trace se for uma exceção
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.format_exception(record.exc_info)
            }
        
        with open(self.filename, "a") as f:
            json.dump(log_entry, f)
            f.write("\n")
    
    def format_exception(self, exc_info):
        import traceback
        return traceback.format_exception(*exc_info)

class LoggerAdapter(logging.LoggerAdapter):
    """Adapter para adicionar contexto extra aos logs"""
    
    def process(self, msg, kwargs):
        # Adiciona contexto extra aos logs
        if 'extra' not in kwargs:
            kwargs['extra'] = {}
        
        kwargs['extra'].update(self.extra)
        return msg, kwargs

def setup_enhanced_logger(
    name: str,
    level: str = "INFO",
    json_file: Optional[str] = None,
    verbose: bool = False,
    console_output: bool = False  # Novo parâmetro para controlar saída no console
) -> logging.Logger:
    """
    Função de conveniência para configurar um logger aprimorado
    """
    # Se não for especificado um arquivo, usa o diretório padrão de logs
    if json_file is None and not console_output:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        json_file = str(log_dir / f"{name}.log")
    
    enhanced_logger = EnhancedLogger(name, level, json_file, verbose, console_output)
    return enhanced_logger.get_logger()

# Logger específico para operações críticas
class OperationLogger:
    """Logger especializado para operações com suporte a métricas"""
    
    def __init__(self, operation_name: str, logger: logging.Logger):
        self.operation_name = operation_name
        self.logger = logger
        self.start_time = None
        self.metrics = {}
    
    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.debug(f"Iniciando operação: {self.operation_name}")  # Mudado de info para debug
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now() - self.start_time).total_seconds()
        
        if exc_type:
            self.logger.error(
                f"Operação {self.operation_name} falhou após {duration:.2f}s: {exc_val}",
                extra={"extra_data": {
                    "operation": self.operation_name,
                    "duration": duration,
                    "error_type": exc_type.__name__,
                    "error_message": str(exc_val),
                    "metrics": self.metrics
                }}
            )
        else:
            self.logger.debug(  # Mudado de info para debug
                f"Operação {self.operation_name} concluída em {duration:.2f}s",
                extra={"extra_data": {
                    "operation": self.operation_name,
                    "duration": duration,
                    "metrics": self.metrics
                }}
            )
    
    def add_metric(self, key: str, value: Any):
        """Adiciona uma métrica à operação"""
        self.metrics[key] = value