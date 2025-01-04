"""
Base Scanner Module for Harbinger Security CLI.

This module provides the abstract base class that all Harbinger scanner modules must inherit from.
It defines the core interface and common functionality for all security scanning operations.

Example Usage:
    class MalwareScanner(BaseScanner):
        @property
        def name(self) -> str:
            return "malware_scanner"
        
        def initialize(self) -> bool:
            # Initialize scanner-specific resources
            return True
        
        async def scan(self, target: str, options: dict) -> ScanResult:
            # Implement scanner-specific logic
            return ScanResult(status=ScanStatus.COMPLETED, findings={})
        
        def cleanup(self) -> None:
            # Clean up scanner-specific resources
            pass
"""

import abc
import asyncio
import enum
import logging
import time
import typing
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, TypeVar, Generic

# Type definitions
T = TypeVar('T')
ScanTarget = TypeVar('ScanTarget')
ScanOptions = Dict[str, Any]

class ScannerError(Exception):
    """Base exception class for all scanner-related errors."""
    pass

class InitializationError(ScannerError):
    """Raised when scanner initialization fails."""
    pass

class ScanError(ScannerError):
    """Raised when a scan operation fails."""
    pass

class ResourceError(ScannerError):
    """Raised when there's an error managing scanner resources."""
    pass

class InvalidStateError(ScannerError):
    """Raised when an operation is attempted in an invalid state."""
    pass

class ConfigurationError(ScannerError):
    """Raised when scanner configuration is invalid."""
    pass

class ScanStatus(enum.Enum):
    """Enumeration of possible scanner states."""
    UNINITIALIZED = "uninitialized"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"
    CLEANING_UP = "cleaning_up"

@dataclass
class ScanProgress:
    """Data class for tracking scan progress."""
    percent_complete: float
    current_operation: str
    started_at: float
    items_processed: int
    items_total: int
    status_message: str

@dataclass
class ScanResult:
    """Data class representing scan results."""
    status: ScanStatus
    findings: Dict[str, Any]
    errors: List[str] = None
    start_time: float = None
    end_time: float = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        self.errors = self.errors or []
        self.metadata = self.metadata or {}
        if not self.start_time:
            self.start_time = time.time()

class BaseScanner(abc.ABC, Generic[ScanTarget]):
    """
    Abstract base class for all Harbinger security scanners.
    
    This class defines the interface and provides common functionality that all
    scanner implementations must follow. It handles scanner lifecycle management,
    resource tracking, and error handling.
    
    The scanner follows a strict state machine:
    UNINITIALIZED -> READY -> RUNNING -> COMPLETED/ERROR -> CLEANING_UP -> READY
    
    All state transitions are validated and enforced. Invalid state transitions
    will raise InvalidStateError.

    Attributes:
        logger: Logger instance for the scanner
        _status: Current status of the scanner
        _progress: Current progress of the scan operation
        _result: Results from the last scan operation
    """

    def __init__(self, timeout: float = 300.0):
        """
        Initialize the base scanner with default values.
        
        Args:
            timeout: Maximum time in seconds for scan operations (default: 300s)
        """
        self.logger = logging.getLogger(self.name)
        self._status = ScanStatus.UNINITIALIZED
        self._progress = ScanProgress(
            percent_complete=0.0,
            current_operation="Not started",
            started_at=0.0,
            items_processed=0,
            items_total=0,
            status_message=""
        )
        self._result: Optional[ScanResult] = None
        self._timeout = timeout
        self._resources: List[Any] = []
        self._scan_task: Optional[asyncio.Task] = None
        self._valid_transitions = {
            ScanStatus.UNINITIALIZED: [ScanStatus.READY],
            ScanStatus.READY: [ScanStatus.RUNNING, ScanStatus.CLEANING_UP],
            ScanStatus.RUNNING: [ScanStatus.COMPLETED, ScanStatus.ERROR],
            ScanStatus.COMPLETED: [ScanStatus.CLEANING_UP],
            ScanStatus.ERROR: [ScanStatus.CLEANING_UP],
            ScanStatus.CLEANING_UP: [ScanStatus.READY, ScanStatus.ERROR]
        }
        self._event_handlers: Dict[str, List[callable]] = {
            'progress_update': [],
            'status_change': [],
            'error': [],
            'completed': []
        }

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Return the unique identifier for this scanner."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """Return the version of this scanner."""
        raise NotImplementedError

    @property
    def status(self) -> ScanStatus:
        """Return the current status of the scanner."""
        return self._status

    @property
    def progress(self) -> ScanProgress:
        """Return the current progress of the scan operation."""
        return self._progress

    @property
    def result(self) -> Optional[ScanResult]:
        """Return the results of the last scan operation."""
        return self._result

    def register_event_handler(self, event_type: str, handler: callable) -> None:
        """
        Register a callback function for specific scanner events.

        Args:
            event_type: Type of event to listen for
            handler: Callback function to handle the event
        """
        if event_type not in self._event_handlers:
            raise ValueError(f"Unknown event type: {event_type}")
        self._event_handlers[event_type].append(handler)

    def _emit_event(self, event_type: str, data: Any) -> None:
        """
        Emit an event to all registered handlers.

        Args:
            event_type: Type of event to emit
            data: Event data to pass to handlers
        """
        for handler in self._event_handlers[event_type]:
            try:
                handler(data)
            except Exception as e:
                self.logger.error(f"Error in event handler: {str(e)}")

    def update_progress(self, **kwargs) -> None:
        """
        Update the scan progress information.

        Args:
            **kwargs: Progress attributes to update

        Raises:
            ValueError: If provided values are invalid
            InvalidStateError: If scanner is not in RUNNING state
        """
        if self.status != ScanStatus.RUNNING:
            raise InvalidStateError("Progress can only be updated while scan is running")

        # Validate progress values
        if 'percent_complete' in kwargs:
            if not 0 <= kwargs['percent_complete'] <= 100:
                raise ValueError("percent_complete must be between 0 and 100")

        if 'items_processed' in kwargs and 'items_total' in kwargs:
            if kwargs['items_processed'] > kwargs['items_total']:
                raise ValueError("items_processed cannot exceed items_total")

        for key, value in kwargs.items():
            if hasattr(self._progress, key):
                setattr(self._progress, key, value)
        
        self._emit_event('progress_update', self._progress)

    def _set_status(self, status: ScanStatus) -> None:
        """
        Update the scanner status and emit status change event.

        Args:
            status: New scanner status

        Raises:
            InvalidStateError: If the status transition is not valid
        """
        if status not in self._valid_transitions.get(self._status, []):
            raise InvalidStateError(
                f"Invalid state transition: {self._status} -> {status}"
            )
        
        self._status = status
        self._emit_event('status_change', status)
        self.logger.info(f"Scanner status changed to: {status}")

    @abc.abstractmethod
    async def initialize(self) -> bool:
        """
        Initialize the scanner and its resources.

        Returns:
            bool: True if initialization was successful, False otherwise

        Raises:
            InitializationError: If initialization fails
        """
        raise NotImplementedError

    async def register_resource(self, resource: Any) -> None:
        """
        Register a resource for tracking and cleanup.

        Args:
            resource: Resource to track
        """
        self._resources.append(resource)

    async def cancel(self) -> None:
        """
        Cancel the current scan operation.

        Raises:
            InvalidStateError: If no scan is running
        """
        if self.status != ScanStatus.RUNNING or not self._scan_task:
            raise InvalidStateError("No scan is currently running")
        
        self._scan_task.cancel()
        try:
            await self._scan_task
        except asyncio.CancelledError:
            self._set_status(ScanStatus.ERROR)
            self._emit_event('error', "Scan cancelled by user")

    @abc.abstractmethod
    async def _do_scan(self, target: ScanTarget, options: ScanOptions) -> ScanResult:
        """
        Implement the actual scanning logic. To be implemented by subclasses.

        Args:
            target: Target to scan
            options: Scan configuration options

        Returns:
            ScanResult: Results of the scan operation
        """
        raise NotImplementedError

    async def scan(self, target: ScanTarget, options: ScanOptions) -> ScanResult:
        """
        Execute the scan operation.

        Args:
            target: Target to scan
            options: Scan configuration options

        Returns:
            ScanResult: Results of the scan operation

        Raises:
            ScanError: If the scan operation fails
            InvalidStateError: If scanner is not in READY state
            asyncio.TimeoutError: If scan exceeds timeout
        """
        if self.status != ScanStatus.READY:
            raise InvalidStateError("Scanner must be in READY state to start scan")

        self._set_status(ScanStatus.RUNNING)
        self._progress = ScanProgress(
            percent_complete=0.0,
            current_operation="Starting scan",
            started_at=time.time(),
            items_processed=0,
            items_total=0,
            status_message="Initializing scan"
        )

        try:
            # Create and store the scan task
            self._scan_task = asyncio.create_task(self._do_scan(target, options))
            
            # Wait for scan completion with timeout
            self._result = await asyncio.wait_for(
                self._scan_task,
                timeout=self._timeout
            )
            
            self._set_status(ScanStatus.COMPLETED)
            self._emit_event('completed', self._result)
            return self._result

        except asyncio.TimeoutError:
            self._set_status(ScanStatus.ERROR)
            error_msg = f"Scan timed out after {self._timeout} seconds"
            self._emit_event('error', error_msg)
            raise

        except asyncio.CancelledError:
            self._set_status(ScanStatus.ERROR)
            self._emit_event('error', "Scan cancelled")
            raise

        except Exception as e:
            self._set_status(ScanStatus.ERROR)
            self._emit_event('error', str(e))
            raise ScanError(f"Scan failed: {str(e)}") from e

        finally:
            self._scan_task = None

    @abc.abstractmethod
    async def cleanup(self) -> None:
        """
        Clean up scanner resources.

        Raises:
            ResourceError: If cleanup fails
        """
        raise NotImplementedError

    async def __aenter__(self):
        """
        Async context manager entry.
        
        Raises:
            InitializationError: If initialization fails
        """
        if self.status != ScanStatus.UNINITIALIZED:
            raise InvalidStateError("Scanner already initialized")
        
        try:
            await self.initialize()
            return self
        except Exception as e:
            raise InitializationError(f"Failed to initialize scanner: {str(e)}") from e

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Async context manager exit.
        
        Ensures cleanup is performed even if an error occurred.
        """
        self._set_status(ScanStatus.CLEANING_UP)
        try:
            await self.cleanup()
            self._set_status(ScanStatus.READY)
        except Exception as e:
            self._set_status(ScanStatus.ERROR)
            self.logger.error(f"Cleanup failed: {str(e)}")
            raise ResourceError(f"Failed to cleanup resources: {str(e)}") from e

    def __repr__(self) -> str:
        """Return string representation of the scanner."""
        return f"{self.__class__.__name__}(name={self.name}, status={self.status})"