"""日志工具：提供带缩进的日志输出功能。"""

import logging


class IndentedLogger:
    """带缩进的日志记录器。"""
    
    def __init__(self, logger_name="IndentedLogger"):
        self.logger = logging.getLogger(logger_name)
    
    def info(self, message, indent=0):
        """带缩进的信息日志。"""
        prefix = "  " * indent
        self.logger.info(f"{prefix}{message}")
    
    def warning(self, message, indent=0):
        """带缩进的警告日志。"""
        prefix = "  " * indent
        self.logger.warning(f"{prefix}{message}")
    
    def error(self, message, indent=0):
        """带缩进的错误日志。"""
        prefix = "  " * indent
        self.logger.error(f"{prefix}{message}")


# 全局日志实例
logger = IndentedLogger()