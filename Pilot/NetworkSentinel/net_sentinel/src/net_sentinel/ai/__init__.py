"""
Net-Sentinel AI Module
~~~~~~~~~~~~~~~~~~~~

This module provides AI-powered guidance and analysis capabilities for network security assessment.
It includes components for LLM management, real-time guidance, and vulnerability analysis.

Basic usage:
    >>> from net_sentinel.ai import AIGuidance
    >>> guidance = AIGuidance()
    >>> recommendations = guidance.analyze_vulnerabilities(scan_results)
"""

from typing import List, Dict, Any, Optional
from enum import Enum
import logging

# Configure module logger
logger = logging.getLogger(__name__)

class ModelType(Enum):
    """Supported LLM model types."""
    LOCAL = "local"
    ENDPOINT = "endpoint"
    HYBRID = "hybrid"

class SecurityRiskLevel(Enum):
    """Security risk levels for AI analysis."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AIConfig:
    """Configuration settings for AI components."""
    def __init__(
        self,
        model_type: ModelType = ModelType.LOCAL,
        model_path: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        api_key: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 500
    ):
        self.model_type = model_type
        self.model_path = model_path
        self.endpoint_url = endpoint_url
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens

    @classmethod
    def from_dict(cls, config: Dict[str, Any]) -> 'AIConfig':
        """Create configuration from dictionary."""
        return cls(
            model_type=ModelType(config.get('model_type', 'local')),
            model_path=config.get('model_path'),
            endpoint_url=config.get('endpoint_url'),
            api_key=config.get('api_key'),
            temperature=float(config.get('temperature', 0.7)),
            max_tokens=int(config.get('max_tokens', 500))
        )

class AIResponse:
    """Structured response from AI analysis."""
    def __init__(
        self,
        recommendations: List[str],
        risk_level: SecurityRiskLevel,
        confidence: float,
        details: Dict[str, Any]
    ):
        self.recommendations = recommendations
        self.risk_level = risk_level
        self.confidence = confidence
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary format."""
        return {
            'recommendations': self.recommendations,
            'risk_level': self.risk_level.value,
            'confidence': self.confidence,
            'details': self.details
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AIResponse':
        """Create response from dictionary."""
        return cls(
            recommendations=data['recommendations'],
            risk_level=SecurityRiskLevel(data['risk_level']),
            confidence=float(data['confidence']),
            details=data['details']
        )

# Import main components
from .llm_manager import LLMManager
from .guidance import AIGuidance

__all__ = [
    'LLMManager',
    'AIGuidance',
    'AIConfig',
    'AIResponse',
    'ModelType',
    'SecurityRiskLevel'
]

# Version info
__version__ = '1.0.0'

def get_default_config() -> AIConfig:
    """
    Returns default AI configuration settings.
    
    Returns:
        AIConfig object with default settings
    """
    return AIConfig(
        model_type=ModelType.LOCAL,
        model_path="models/security_llm",
        temperature=0.7,
        max_tokens=500
    )

def validate_config(config: AIConfig) -> bool:
    """
    Validates AI configuration settings.
    
    Args:
        config: AIConfig object to validate
        
    Returns:
        bool indicating if configuration is valid
        
    Raises:
        ValueError: If configuration is invalid
    """
    if config.model_type == ModelType.LOCAL and not config.model_path:
        raise ValueError("Local model requires model_path")
    
    if config.model_type == ModelType.ENDPOINT and not config.endpoint_url:
        raise ValueError("Endpoint model requires endpoint_url")
    
    if config.temperature < 0 or config.temperature > 1:
        raise ValueError("Temperature must be between 0 and 1")
    
    if config.max_tokens < 1:
        raise ValueError("max_tokens must be positive")
    
    return True

def format_guidance(response: AIResponse) -> str:
    """
    Formats AI guidance response for display.
    
    Args:
        response: AIResponse object to format
        
    Returns:
        Formatted string representation of the guidance
    """
    output = [
        f"Risk Level: {response.risk_level.value.upper()}",
        f"Confidence: {response.confidence:.2f}",
        "\nRecommendations:",
        *[f"- {rec}" for rec in response.recommendations],
        "\nDetails:",
        *[f"{k}: {v}" for k, v in response.details.items()]
    ]
    
    return "\n".join(output)