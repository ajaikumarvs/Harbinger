"""
Tests for Net-Sentinel AI Components
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides test cases for the AI guidance and
analysis components of Net-Sentinel.
"""

import pytest
import json
from unittest.mock import MagicMock, patch
from datetime import datetime
import asyncio
from pathlib import Path

from net_sentinel.ai import (
    AIGuidance,
    AIConfig,
    AIResponse,
    ModelType,
    SecurityRiskLevel,
    LLMManager
)
from tests import BaseTestCase, async_test, TestConfig

class TestAIGuidance(BaseTestCase):
    """Test cases for AI guidance functionality."""
    
    def setup_method(self, method):
        """Set up test method."""
        super().setup_method(method)
        self.config = AIConfig(
            model_type=ModelType.LOCAL,
            model_path="models/test_model",
            temperature=0.7
        )
        self.guidance = AIGuidance(self.config)
    
    @pytest.mark.asyncio
    async def test_analyze_vulnerabilities(self, mock_llm_response):
        """Test vulnerability analysis."""
        # Prepare test data
        scan_results = {
            'vulnerabilities': [
                {
                    'title': 'Open SSH Port',
                    'severity': 'high',
                    'description': 'SSH service is exposed'
                }
            ],
            'hosts': [
                {
                    'ip': '192.168.1.1',
                    'ports': [22]
                }
            ]
        }
        
        # Mock LLM response
        mock_llm_response.return_value = json.dumps({
            'recommendations': [
                'Restrict SSH access to specific IPs',
                'Implement key-based authentication'
            ],
            'risk_level': 'high',
            'confidence': 0.85
        })
        
        # Run analysis
        response = await self.guidance.analyze_vulnerabilities(scan_results)
        
        # Verify response
        assert isinstance(response, AIResponse)
        assert response.risk_level == SecurityRiskLevel.HIGH
        assert len(response.recommendations) == 2
        assert response.confidence > 0.8
    
    @pytest.mark.asyncio
    async def test_provide_realtime_guidance(self):
        """Test real-time guidance during scanning."""
        current_operation = "port_scanning"
        scan_status = {
            'progress': 50,
            'current_host': '192.168.1.1',
            'findings': []
        }
        
        guidance = await self.guidance.provide_realtime_guidance(
            current_operation,
            scan_status
        )
        
        assert isinstance(guidance, list)
        assert len(guidance) > 0
        assert all(isinstance(g, str) for g in guidance)
    
    @pytest.mark.asyncio
    async def test_suggest_next_steps(self):
        """Test next steps suggestion."""
        current_findings = {
            'vulnerabilities': [
                {
                    'title': 'Weak SSL Configuration',
                    'severity': 'medium'
                }
            ]
        }
        
        steps, confidence = await self.guidance.suggest_next_steps(
            current_findings
        )
        
        assert isinstance(steps, list)
        assert isinstance(confidence, dict)
        assert all(isinstance(step, str) for step in steps)
        assert all(0 <= score <= 1 for score in confidence.values())

class TestLLMManager(BaseTestCase):
    """Test cases for LLM management."""
    
    def setup_method(self, method):
        """Set up test method."""
        super().setup_method(method)
        self.config = AIConfig(
            model_type=ModelType.LOCAL,
            model_path="models/test_model"
        )
        self.llm = LLMManager(self.config)
    
    @pytest.mark.asyncio
    async def test_generate_local(self):
        """Test local model generation."""
        prompt = "Analyze the following security findings..."
        
        with patch('torch.cuda.is_available', return_value=False):
            response = await self.llm.generate(prompt)
            
        assert isinstance(response, str)
        assert len(response) > 0
    
    @pytest.mark.asyncio
    async def test_generate_endpoint(self):
        """Test endpoint model generation."""
        config = AIConfig(
            model_type=ModelType.ENDPOINT,
            endpoint_url="https://api.example.com/v1/generate",
            api_key="test_key"
        )
        llm = LLMManager(config)
        
        prompt = "Recommend security measures..."
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value.status = 200
            mock_post.return_value.__aenter__.return_value.json = \
                AsyncMock(return_value={'choices': [{'text': 'Test response'}]})
            
            response = await llm.generate(prompt)
            
        assert isinstance(response, str)
        assert len(response) > 0
    
    @pytest.mark.asyncio
    async def test_generate_hybrid(self):
        """Test hybrid model generation."""
        config = AIConfig(
            model_type=ModelType.HYBRID,
            model_path="models/test_model",
            endpoint_url="https://api.example.com/v1/generate",
            api_key="test_key"
        )
        llm = LLMManager(config)
        
        prompt = "Security analysis required..."
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            # Mock endpoint failure
            mock_post.return_value.__aenter__.return_value.status = 500
            
            # Should fallback to local model
            response = await llm.generate(prompt)
            
        assert isinstance(response, str)
        assert len(response) > 0

class TestAIConfig(BaseTestCase):
    """Test cases for AI configuration."""
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Valid local config
        config = AIConfig(
            model_type=ModelType.LOCAL,
            model_path="models/test_model"
        )
        assert config.validate()
        
        # Invalid endpoint config (missing URL)
        with pytest.raises(ValueError):
            AIConfig(
                model_type=ModelType.ENDPOINT,
                api_key="test_key"
            ).validate()
        
        # Invalid temperature
        with pytest.raises(ValueError):
            AIConfig(
                model_type=ModelType.LOCAL,
                model_path="models/test_model",
                temperature=1.5
            ).validate()
    
    def test_config_from_dict(self):
        """Test configuration creation from dictionary."""
        config_dict = {
            'model_type': 'local',
            'model_path': 'models/test_model',
            'temperature': 0.7,
            'max_tokens': 500
        }
        
        config = AIConfig.from_dict(config_dict)
        
        assert config.model_type == ModelType.LOCAL
        assert config.model_path == 'models/test_model'
        assert config.temperature == 0.7
        assert config.max_tokens == 500

@pytest.fixture
def mock_llm_response():
    """Provide mock LLM response."""
    with patch('net_sentinel.ai.llm_manager.LLMManager.generate') as mock:
        yield mock

class AsyncMock(MagicMock):
    """Mock for async functions."""
    async def __call__(self, *args, **kwargs):
        return super(AsyncMock, self).__call__(*args, **kwargs)

@pytest.fixture
def sample_vulnerability():
    """Provide sample vulnerability data."""
    return {
        'title': 'Critical Service Exposed',
        'severity': 'critical',
        'description': 'A critical service is exposed to the network',
        'affected_hosts': ['192.168.1.1'],
        'technical_details': {
            'service': 'database',
            'port': 5432,
            'version': '9.6.3'
        }
    }

@pytest.fixture
def mock_model_response():
    """Provide mock model response."""
    return {
        'recommendations': [
            'Restrict network access',
            'Update to latest version',
            'Enable encryption'
        ],
        'risk_level': 'critical',
        'confidence': 0.95,
        'details': {
            'cve_matches': ['CVE-2024-1234'],
            'exploit_likelihood': 'high'
        }
    }