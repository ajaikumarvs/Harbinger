"""
Logging Module for Net-Sentinel
~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides configurable logging functionality with
multiple handlers and formatters for different logging needs.
"""

import logging
import sys
from typing import Optional, Dict, Any, Union
from pathlib import Path
import json
from datetime import datetime
import os
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import threading
from queue import Queue
import atexit

class LogLevel:
    """Logging level definitions."""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

class CustomFormatter(logging.Formatter):
    """
    Custom formatter with color support and additional fields.
    """
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[41m', # Red background
        'RESET': '\033[0m'      # Reset
    }
    
    def __init__(
        self,
        colored: bool = True,
        include_thread: bool = True
    ):
        """
        Initialize formatter.
        
        Args:
            colored: Whether to use colored output
            include_thread: Whether to include thread information
        """
        super().__init__()
        self.colored = colored and sys.platform != 'win32'  # Disable colors on Windows
        self.include_thread = include_thread
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record."""
        # Create basic format
        format_parts = [
            "%(asctime)s",
            "[%(levelname)s]",
            "%(name)s",
            "%(message)s"
        ]
        
        # Add thread info if requested
        if self.include_thread:
            format_parts.insert(2, "[Thread-%(thread)d]")
        
        # Build format string
        format_str = " ".join(format_parts)
        
        # Add colors if enabled
        if self.colored:
            color = self.COLORS.get(record.levelname, "")
            reset = self.COLORS['RESET']
            format_str = f"{color}{format_str}{reset}"
        
        # Set format string and format record
        self._style._fmt = format_str
        return super().format(record)

class AsyncHandler(logging.Handler):
    """
    Asynchronous logging handler using a queue.
    """
    
    def __init__(self, handler: logging.Handler):
        """
        Initialize async handler.
        
        Args:
            handler: Base handler to wrap
        """
        super().__init__()
        self.handler = handler
        self.queue: Queue = Queue()
        self.thread = threading.Thread(target=self._process_logs)
        self.thread.daemon = True
        self.thread.start()
        atexit.register(self.close)
    
    def emit(self, record: logging.LogRecord) -> None:
        """Add record to queue."""
        self.queue.put(record)
    
    def _process_logs(self) -> None:
        """Process log records from queue."""
        while True:
            try:
                record = self.queue.get()
                if record is None:
                    break
                self.handler.emit(record)
            except Exception:
                pass
    
    def close(self) -> None:
        """Clean up handler resources."""
        self.queue.put(None)
        self.thread.join()
        self.handler.close()
        super().close()

def setup_logging(
    level: int = LogLevel.INFO,
    log_file: Optional[Union[str, Path]] = None,
    max_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    async_logging: bool = True,
    colored_output: bool = True,
    include_thread_info: bool = True,
    json_format: bool = False
) -> logging.Logger:
    """
    Set up logging configuration.
    
    Args:
        level: Logging level
        log_file: Optional log file path
        max_size: Maximum log file size in bytes
        backup_count: Number of backup files to keep
        async_logging: Whether to use async logging
        colored_output: Whether to use colored output
        include_thread_info: Whether to include thread info
        json_format: Whether to use JSON format
        
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger("net_sentinel")
    logger.setLevel(level)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    # Set formatter
    if json_format:
        formatter = _create_json_formatter()
    else:
        formatter = CustomFormatter(
            colored=colored_output,
            include_thread=include_thread_info
        )
    
    console_handler.setFormatter(formatter)
    
    # Wrap in async handler if requested
    if async_logging:
        console_handler = AsyncHandler(console_handler)
    
    logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(level)
        
        # Use JSON formatter for file by default
        file_handler.setFormatter(_create_json_formatter())
        
        if async_logging:
            file_handler = AsyncHandler(file_handler)
        
        logger.addHandler(file_handler)
    
    return logger

def _create_json_formatter() -> logging.Formatter:
    """Create JSON formatter."""
    return logging.Formatter(
        lambda r: json.dumps({
            'timestamp': datetime.utcfromtimestamp(r.created).isoformat(),
            'level': r.levelname,
            'logger': r.name,
            'thread': r.thread,
            'message': r.getMessage(),
            'path': r.pathname,
            'line': r.lineno,
            'function': r.funcName
        }, default=str)
    )

class LoggerContext:
    """
    Context manager for temporary logger settings.
    """
    
    def __init__(
        self,
        logger: logging.Logger,
        level: Optional[int] = None,
        handlers: Optional[list] = None
    ):
        """
        Initialize context.
        
        Args:
            logger: Logger to modify
            level: Temporary log level
            handlers: Temporary handlers
        """
        self.logger = logger
        self.level = level
        self.handlers = handlers
        self.old_level = logger.level
        self.old_handlers = logger.handlers.copy()
    
    def __enter__(self) -> logging.Logger:
        """Enter context."""
        if self.level is not None:
            self.logger.setLevel(self.level)
        
        if self.handlers is not None:
            self.logger.handlers.clear()
            for handler in self.handlers:
                self.logger.addHandler(handler)
        
        return self.logger
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context."""
        self.logger.setLevel(self.old_level)
        self.logger.handlers = self.old_handlers

class ScanLogger:
    """
    Specialized logger for scan operations.
    """
    
    def __init__(self, base_logger: logging.Logger):
        """
        Initialize scan logger.
        
        Args:
            base_logger: Base logger to extend
        """
        self.logger = base_logger
        self.start_time = None
        self.scan_id = None
    
    def start_scan(self, scan_id: str) -> None:
        """
        Start scan logging session.
        
        Args:
            scan_id: Unique scan identifier
        """
        self.start_time = datetime.now()
        self.scan_id = scan_id
        self.logger.info(
            "Starting scan",
            extra={
                'scan_id': scan_id,
                'start_time': self.start_time.isoformat()
            }
        )
    
    def end_scan(self) -> None:
        """End scan logging session."""
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            self.logger.info(
                "Scan completed",
                extra={
                    'scan_id': self.scan_id,
                    'duration': duration
                }
            )
    
    def log_finding(
        self,
        severity: str,
        title: str,
        description: str,
        **kwargs
    ) -> None:
        """
        Log security finding.
        
        Args:
            severity: Finding severity
            title: Finding title
            description: Finding description
            **kwargs: Additional fields
        """
        self.logger.warning(
            f"Security finding: {title}",
            extra={
                'scan_id': self.scan_id,
                'finding_severity': severity,
                'finding_title': title,
                'finding_description': description,
                **kwargs
            }
        )
    
    def log_progress(
        self,
        stage: str,
        progress: float,
        status: str = "in_progress"
    ) -> None:
        """
        Log scan progress.
        
        Args:
            stage: Current scan stage
            progress: Progress percentage
            status: Current status
        """
        self.logger.info(
            f"Scan progress: {stage}",
            extra={
                'scan_id': self.scan_id,
                'stage': stage,
                'progress': progress,
                'status': status
            }
        )