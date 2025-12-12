# core/api_client.py
"""
API Client for AI/ML services with Zero-Trust security headers.
Handles authentication, request formatting, and response validation.
"""
import requests
import json
from typing import Dict, Any, Optional
from .logger import get_logger

logger = get_logger(__name__)


class APIClient:
    """HTTPS client with authentication and zero-trust headers."""
    
    def __init__(self, base_url: str, token: str, timeout: int = 20):
        """
        Initialize API client.
        
        Args:
            base_url: Base URL for API endpoints
            token: Authentication token
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Zero-Trust": "enabled",
            "X-Client-Version": "1.0.0"
        }
        logger.info(f"APIClient initialized for {self.base_url}")

    def post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send POST request to endpoint.
        
        Args:
            endpoint: API endpoint path
            payload: Request payload dictionary
            
        Returns:
            Response JSON as dictionary
            
        Raises:
            requests.HTTPError: On HTTP error responses
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        logger.info(f"POST {url}")
        logger.debug(f"Payload: {json.dumps(payload, indent=2)}")
        
        try:
            resp = requests.post(
                url,
                headers=self.headers,
                data=json.dumps(payload),
                timeout=self.timeout
            )
            resp.raise_for_status()
            response_data = resp.json()
            logger.info(f"Response status: {resp.status_code}")
            return response_data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            raise

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Send GET request to endpoint.
        
        Args:
            endpoint: API endpoint path
            params: Query parameters
            
        Returns:
            Response JSON as dictionary
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        logger.info(f"GET {url}")
        
        try:
            resp = requests.get(
                url,
                headers=self.headers,
                params=params,
                timeout=self.timeout
            )
            resp.raise_for_status()
            response_data = resp.json()
            logger.info(f"Response status: {resp.status_code}")
            return response_data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            raise

    def put(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send PUT request to endpoint."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        logger.info(f"PUT {url}")
        
        try:
            resp = requests.put(
                url,
                headers=self.headers,
                data=json.dumps(payload),
                timeout=self.timeout
            )
            resp.raise_for_status()
            return resp.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            raise

    def delete(self, endpoint: str) -> Dict[str, Any]:
        """Send DELETE request to endpoint."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        logger.info(f"DELETE {url}")
        
        try:
            resp = requests.delete(
                url,
                headers=self.headers,
                timeout=self.timeout
            )
            resp.raise_for_status()
            return resp.json() if resp.content else {}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            raise
        
    def autofill_suggest(self, data):
        """
        Get autofill suggestions based on input context
    
        Args:
            data (dict): Input data with field and context information
        
        Returns:
            dict: Autofill suggestions with confidence scores
        """
        endpoint = "/autofill/suggest"
        return self.post(endpoint, payload=data)