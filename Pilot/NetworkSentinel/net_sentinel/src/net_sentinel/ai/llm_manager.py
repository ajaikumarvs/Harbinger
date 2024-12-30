"""
LLM Manager Module for Net-Sentinel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module handles the loading, management, and interaction with
Large Language Models for security analysis and guidance.
"""

import logging
import json
from typing import Dict, Any, Optional, Union
from pathlib import Path
import asyncio
from concurrent.futures import ThreadPoolExecutor
import torch
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    Pipeline,
    pipeline
)
import requests
from functools import lru_cache

from . import AIConfig, ModelType

logger = logging.getLogger(__name__)

class LLMManager:
    """
    Manages LLM operations including model loading, inference, and response generation.
    """
    
    def __init__(self, config: AIConfig):
        """
        Initialize the LLM manager.
        
        Args:
            config: AI configuration object
        """
        self.config = config
        self.model = None
        self.tokenizer = None
        self.pipeline = None
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._setup_model()
    
    def _setup_model(self) -> None:
        """Set up the model based on configuration."""
        try:
            if self.config.model_type == ModelType.LOCAL:
                self._setup_local_model()
            elif self.config.model_type == ModelType.ENDPOINT:
                self._validate_endpoint()
            elif self.config.model_type == ModelType.HYBRID:
                self._setup_hybrid_model()
            else:
                raise ValueError(f"Unsupported model type: {self.config.model_type}")
                
        except Exception as e:
            logger.error(f"Failed to set up model: {str(e)}")
            raise
    
    def _setup_local_model(self) -> None:
        """Set up local model and tokenizer."""
        if not self.config.model_path:
            raise ValueError("Model path not specified for local model")
            
        model_path = Path(self.config.model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found at {model_path}")
            
        try:
            logger.info(f"Loading model from {model_path}")
            self.tokenizer = AutoTokenizer.from_pretrained(str(model_path))
            
            # Load model with appropriate settings for security analysis
            self.model = AutoModelForCausalLM.from_pretrained(
                str(model_path),
                torch_dtype=torch.float16,
                device_map="auto",
                low_cpu_mem_usage=True,
                trust_remote_code=False  # Security: Don't execute remote code
            )
            
            # Set up generation pipeline
            self.pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                device_map="auto"
            )
            
            logger.info("Local model setup complete")
            
        except Exception as e:
            logger.error(f"Failed to load local model: {str(e)}")
            raise
    
    def _validate_endpoint(self) -> None:
        """Validate API endpoint configuration."""
        if not self.config.endpoint_url:
            raise ValueError("Endpoint URL not specified")
            
        if not self.config.api_key:
            raise ValueError("API key not specified for endpoint model")
    
    def _setup_hybrid_model(self) -> None:
        """Set up hybrid model configuration."""
        self._setup_local_model()  # Load local model as fallback
        self._validate_endpoint()   # Validate endpoint for primary use
    
    @lru_cache(maxsize=1024)
    def _get_cached_response(self, prompt: str) -> Optional[str]:
        """
        Get cached response for a prompt.
        
        Args:
            prompt: Input prompt
            
        Returns:
            Cached response if available, None otherwise
        """
        return None  # Implement caching if needed
    
    async def generate(
        self,
        prompt: str,
        max_length: Optional[int] = None,
        temperature: Optional[float] = None,
        stop_sequences: Optional[list] = None
    ) -> str:
        """
        Generate response from the model.
        
        Args:
            prompt: Input prompt
            max_length: Optional maximum length of response
            temperature: Optional temperature for generation
            stop_sequences: Optional list of sequences to stop generation
            
        Returns:
            Generated response
        """
        # Check cache first
        cached = self._get_cached_response(prompt)
        if cached:
            return cached
        
        try:
            if self.config.model_type == ModelType.LOCAL:
                return await self._generate_local(
                    prompt,
                    max_length,
                    temperature,
                    stop_sequences
                )
            elif self.config.model_type == ModelType.ENDPOINT:
                return await self._generate_endpoint(
                    prompt,
                    max_length,
                    temperature,
                    stop_sequences
                )
            else:  # Hybrid
                return await self._generate_hybrid(
                    prompt,
                    max_length,
                    temperature,
                    stop_sequences
                )
                
        except Exception as e:
            logger.error(f"Generation failed: {str(e)}")
            raise
    
    async def _generate_local(
        self,
        prompt: str,
        max_length: Optional[int],
        temperature: Optional[float],
        stop_sequences: Optional[list]
    ) -> str:
        """Generate response using local model."""
        loop = asyncio.get_event_loop()
        
        def _generate():
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
            
            with torch.no_grad():
                outputs = self.pipeline(
                    prompt,
                    max_length=max_length or self.config.max_tokens,
                    temperature=temperature or self.config.temperature,
                    do_sample=True,
                    num_return_sequences=1,
                    pad_token_id=self.tokenizer.eos_token_id,
                    stop_sequences=stop_sequences
                )
            
            return outputs[0]['generated_text']
        
        return await loop.run_in_executor(self._executor, _generate)
    
    async def _generate_endpoint(
        self,
        prompt: str,
        max_length: Optional[int],
        temperature: Optional[float],
        stop_sequences: Optional[list]
    ) -> str:
        """Generate response using API endpoint."""
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "prompt": prompt,
            "max_tokens": max_length or self.config.max_tokens,
            "temperature": temperature or self.config.temperature
        }
        
        if stop_sequences:
            data["stop"] = stop_sequences
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.config.endpoint_url,
                headers=headers,
                json=data
            ) as response:
                if response.status != 200:
                    raise RuntimeError(
                        f"API request failed: {response.status}"
                    )
                
                result = await response.json()
                return result["choices"][0]["text"]
    
    async def _generate_hybrid(
        self,
        prompt: str,
        max_length: Optional[int],
        temperature: Optional[float],
        stop_sequences: Optional[list]
    ) -> str:
        """Generate response using hybrid approach."""
        try:
            # Try endpoint first
            return await self._generate_endpoint(
                prompt,
                max_length,
                temperature,
                stop_sequences
            )
        except Exception as e:
            logger.warning(f"Endpoint generation failed, falling back to local: {str(e)}")
            return await self._generate_local(
                prompt,
                max_length,
                temperature,
                stop_sequences
            )
    
    def __del__(self):
        """Cleanup resources."""
        if self._executor:
            self._executor.shutdown(wait=True)