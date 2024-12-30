"""
AI Guidance Module for Net-Sentinel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides intelligent security guidance and recommendations
based on network scanning and vulnerability assessment results.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import json

from .llm_manager import LLMManager
from . import AIConfig, AIResponse, SecurityRiskLevel

logger = logging.getLogger(__name__)

@dataclass
class GuidanceContext:
    """Context information for AI guidance generation."""
    scan_type: str
    target_type: str
    scan_depth: str
    timestamp: str
    environment_tags: List[str]

class AIGuidance:
    """
    Provides AI-powered security guidance and recommendations.
    """
    
    def __init__(self, config: Optional[AIConfig] = None):
        """
        Initialize the AI guidance system.
        
        Args:
            config: Optional AI configuration. If None, uses default config.
        """
        self.config = config or AIConfig()
        self.llm = LLMManager(self.config)
        
    async def analyze_vulnerabilities(
        self,
        scan_results: Dict[str, Any],
        context: Optional[GuidanceContext] = None
    ) -> AIResponse:
        """
        Analyze vulnerability scan results and provide recommendations.
        
        Args:
            scan_results: Dictionary containing scan results
            context: Optional context information for better analysis
            
        Returns:
            AIResponse containing recommendations and risk assessment
        """
        # Prepare input for LLM
        prompt = self._build_analysis_prompt(scan_results, context)
        
        try:
            # Get LLM response
            raw_response = await self.llm.generate(prompt)
            
            # Parse and validate response
            parsed_response = self._parse_llm_response(raw_response)
            
            # Enhance recommendations with context
            enhanced_response = self._enhance_recommendations(parsed_response, context)
            
            return enhanced_response
            
        except Exception as e:
            logger.error(f"Failed to analyze vulnerabilities: {str(e)}")
            raise
    
    async def provide_realtime_guidance(
        self,
        current_operation: str,
        scan_status: Dict[str, Any],
        previous_findings: Optional[List[Dict[str, Any]]] = None
    ) -> List[str]:
        """
        Provide real-time guidance during scanning operations.
        
        Args:
            current_operation: Current scanning operation
            scan_status: Current status of the scan
            previous_findings: Optional list of previous findings
            
        Returns:
            List of guidance suggestions
        """
        prompt = self._build_realtime_prompt(
            current_operation,
            scan_status,
            previous_findings
        )
        
        try:
            response = await self.llm.generate(prompt)
            return self._parse_realtime_guidance(response)
        except Exception as e:
            logger.error(f"Failed to provide real-time guidance: {str(e)}")
            return []
    
    async def suggest_next_steps(
        self,
        current_findings: Dict[str, Any],
        scan_history: Optional[List[Dict[str, Any]]] = None
    ) -> Tuple[List[str], Dict[str, float]]:
        """
        Suggest next steps based on current findings and scan history.
        
        Args:
            current_findings: Current scan findings
            scan_history: Optional history of previous scans
            
        Returns:
            Tuple of (suggested steps, confidence scores)
        """
        prompt = self._build_next_steps_prompt(current_findings, scan_history)
        
        try:
            response = await self.llm.generate(prompt)
            return self._parse_next_steps(response)
        except Exception as e:
            logger.error(f"Failed to suggest next steps: {str(e)}")
            return [], {}

    def _build_analysis_prompt(
        self,
        scan_results: Dict[str, Any],
        context: Optional[GuidanceContext]
    ) -> str:
        """Build prompt for vulnerability analysis."""
        prompt_parts = [
            "Analyze the following network security scan results and provide recommendations:\n",
            json.dumps(scan_results, indent=2),
            "\nConsider the following aspects:",
            "1. Severity of identified vulnerabilities",
            "2. Potential attack vectors",
            "3. Recommended mitigations",
            "4. Priority of actions"
        ]
        
        if context:
            prompt_parts.extend([
                f"\nScan Type: {context.scan_type}",
                f"Target Type: {context.target_type}",
                f"Environment: {', '.join(context.environment_tags)}"
            ])
        
        return "\n".join(prompt_parts)

    def _build_realtime_prompt(
        self,
        current_operation: str,
        scan_status: Dict[str, Any],
        previous_findings: Optional[List[Dict[str, Any]]]
    ) -> str:
        """Build prompt for real-time guidance."""
        prompt_parts = [
            f"Current Operation: {current_operation}",
            "\nCurrent Status:",
            json.dumps(scan_status, indent=2)
        ]
        
        if previous_findings:
            prompt_parts.extend([
                "\nPrevious Findings:",
                json.dumps(previous_findings, indent=2)
            ])
        
        prompt_parts.append("\nProvide guidance for the current operation.")
        return "\n".join(prompt_parts)

    def _build_next_steps_prompt(
        self,
        current_findings: Dict[str, Any],
        scan_history: Optional[List[Dict[str, Any]]]
    ) -> str:
        """Build prompt for next steps suggestions."""
        prompt_parts = [
            "Based on the following findings and history, suggest next steps:\n",
            "\nCurrent Findings:",
            json.dumps(current_findings, indent=2)
        ]
        
        if scan_history:
            prompt_parts.extend([
                "\nScan History:",
                json.dumps(scan_history, indent=2)
            ])
        
        return "\n".join(prompt_parts)

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse and validate LLM response."""
        try:
            # Extract structured data from LLM response
            parsed = json.loads(response)
            
            required_fields = ['recommendations', 'risk_level', 'confidence']
            if not all(field in parsed for field in required_fields):
                raise ValueError("Missing required fields in LLM response")
            
            return parsed
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response: {str(e)}")
            raise ValueError("Invalid LLM response format")

    def _parse_realtime_guidance(self, response: str) -> List[str]:
        """Parse real-time guidance response."""
        try:
            parsed = json.loads(response)
            if not isinstance(parsed, list):
                raise ValueError("Expected list of guidance items")
            return parsed
        except json.JSONDecodeError:
            # Fallback to simple line splitting if not JSON
            return [line.strip() for line in response.split('\n') if line.strip()]

    def _parse_next_steps(
        self,
        response: str
    ) -> Tuple[List[str], Dict[str, float]]:
        """Parse next steps suggestions and confidence scores."""
        try:
            parsed = json.loads(response)
            steps = parsed.get('steps', [])
            scores = parsed.get('confidence_scores', {})
            return steps, scores
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse next steps: {str(e)}")
            return [], {}

    def _enhance_recommendations(
        self,
        parsed_response: Dict[str, Any],
        context: Optional[GuidanceContext]
    ) -> AIResponse:
        """Enhance recommendations with context information."""
        recommendations = parsed_response['recommendations']
        risk_level = SecurityRiskLevel(parsed_response['risk_level'])
        confidence = float(parsed_response['confidence'])
        
        details = parsed_response.get('details', {})
        if context:
            details.update({
                'scan_type': context.scan_type,
                'environment': context.environment_tags,
                'timestamp': context.timestamp
            })
        
        return AIResponse(
            recommendations=recommendations,
            risk_level=risk_level,
            confidence=confidence,
            details=details
        )