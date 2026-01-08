# core/api_client.py
"""
API Client Module for AI/ML Services

HTTP client for communicating with AI/ML microservices. Handles authentication
via bearer tokens, request/response formatting, timeout management, and error
handling with comprehensive logging.

Implements Zero-Trust security:
    - Bearer token authentication on every request
    - X-Zero-Trust and X-Client-Version security headers
    - HTTP error validation and exception raising
    - Structured logging of all requests/responses

Supported Methods:
    - GET: Retrieve resources with query parameters
    - POST: Create/update resources with JSON payload
    - PUT: Full resource replacement (idempotent)
    - DELETE: Remove resources

Dependencies:
    - requests: HTTP client library
    - json: JSON serialization
    - .logger: Custom logging module
"""

import requests
import json
from typing import Dict, Any, Optional
from .logger import get_logger

logger = get_logger(__name__)


class APIClient:
    """
    HTTPS client with Zero-Trust authentication and security headers.
    
    Encapsulates HTTP communication with remote AI/ML microservices.
    Handles authentication, request formatting, response parsing, and
    error management with structured logging.
    
    Attributes:
        base_url (str): Base URL for API endpoints (trailing slash removed)
        timeout (int): Request timeout in seconds (default: 20)
        headers (dict): HTTP headers (Authorization, X-Zero-Trust, etc.)
    
    Example:
        >>> client = APIClient(
        ...     base_url="https://api.example.com",
        ...     token="sk-abc123...",
        ...     timeout=20
        ... )
        >>> 
        >>> # POST request
        >>> result = client.post("threats/classify", {"text": "suspicious email"})
        >>> print(result['label'])
        'phishing'
        >>> 
        >>> # GET request with pagination
        >>> threats = client.get("threats/list", params={"limit": 10})
        >>> 
        >>> # Convenience method
        >>> suggestions = client.autofill_suggest({"field": "email", "context": "john"})
    
    Use Cases:
        - Threat classification
        - Data summarization
        - Metric computation
        - Guardrail validation
        - Autofill suggestions
    """
    
    def __init__(self, base_url: str, token: str, timeout: int = 20):
        """
        Initialize API client with authentication.
        
        Args:
            base_url (str): Base URL for API endpoints (https://api.example.com)
            token (str): Bearer token for authentication (sk-abc123...)
            timeout (int): Request timeout in seconds (default: 20)
        
        Example:
            >>> client = APIClient(
            ...     base_url="https://api.example.com",
            ...     token=os.environ['API_TOKEN'],
            ...     timeout=30
            ... )
        
        Notes:
            - Trailing slashes automatically removed from base_url
            - Token should be loaded from environment, not hardcoded
            - Timeout applies to all requests (GET, POST, PUT, DELETE)
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
        Send POST request with JSON payload.
        
        Args:
            endpoint (str): API endpoint path (e.g., "threats/classify")
            payload (dict): Request body as JSON-serializable dict
        
        Returns:
            dict: Response JSON parsed as dictionary
        
        Raises:
            requests.HTTPError: On non-2xx status codes
            requests.Timeout: If request exceeds timeout
            requests.ConnectionError: If connection fails
        
        Example:
            >>> response = client.post(
            ...     endpoint="threats/classify",
            ...     payload={"text": "Click here to win!", "model": "v2"}
            ... )
            >>> print(response['label'], response['confidence'])
            phishing 0.92
            
            >>> # With error handling
            >>> try:
            ...     result = client.post("summarize", {"text": "..."})
            ... except requests.HTTPError as e:
            ...     print(f"API Error: {e.response.status_code}")
        
        Performance: O(n) where n = payload + response size
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
        Send GET request with optional query parameters.
        
        Args:
            endpoint (str): API endpoint path (e.g., "threats/list")
            params (dict, optional): Query parameters for filtering/pagination
        
        Returns:
            dict: Response JSON parsed as dictionary
        
        Raises:
            requests.HTTPError: On non-2xx status codes
            requests.Timeout: If request exceeds timeout
            requests.ConnectionError: If connection fails
        
        Example:
            >>> # Get with pagination
            >>> response = client.get(
            ...     endpoint="threats/list",
            ...     params={"limit": 20, "offset": 0, "type": "phishing"}
            ... )
            >>> print(f"Total: {response['total']}")
            >>> for threat in response['threats']:
            ...     print(f"  {threat['id']}: {threat['type']}")
            
            >>> # Get status
            >>> status = client.get(endpoint="status")
            >>> print(f"API Version: {status['version']}")
        
        Performance: O(n) where n = query string + response size
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
        """
        Send PUT request for full resource replacement (idempotent).
        
        Args:
            endpoint (str): API endpoint path (e.g., "threats/123")
            payload (dict): Complete resource representation
        
        Returns:
            dict: Response JSON with updated resource
        
        Raises:
            requests.HTTPError: On non-2xx status codes
            requests.Timeout: If request exceeds timeout
            requests.ConnectionError: If connection fails
        
        Example:
            >>> updated = client.put(
            ...     endpoint="threats/12345",
            ...     payload={
            ...         "id": 12345,
            ...         "status": "resolved",
            ...         "resolved_by": "admin"
            ...     }
            ... )
            >>> print(f"Updated: {updated['status']}")
        
        Notes:
            - PUT is idempotent (safe to retry)
            - Requires full resource representation
            - Different from PATCH (partial update)
        """
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
        """
        Send DELETE request to remove a resource.
        
        Args:
            endpoint (str): API endpoint path (e.g., "threats/123")
        
        Returns:
            dict: Response JSON if provided, else empty dict {}
        
        Raises:
            requests.HTTPError: On non-2xx status codes
            requests.Timeout: If request exceeds timeout
            requests.ConnectionError: If connection fails
        
        Example:
            >>> result = client.delete(endpoint="threats/12345")
            >>> if result.get('deleted'):
            ...     print("Threat removed successfully")
        
        Notes:
            - DELETE is idempotent
            - Many endpoints return 204 No Content (empty response)
            - Second delete may return 404 (already deleted)
        """
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
        
    def autofill_suggest(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get autofill suggestions for form fields.
        
        Convenience method for requesting email, phone, or address suggestions.
        
        Args:
            data (dict): {"field": type, "context": input_prefix}
                field: 'email', 'phone', or 'address'
                context: User input (e.g., 'john.doe', '555', 'Main')
        
        Returns:
            dict: {'suggestions': list[str], 'confidence': float}
        
        Raises:
            requests.HTTPError: On HTTP errors
            requests.Timeout: If request exceeds timeout
        
        Example:
            >>> # Email suggestions
            >>> result = client.autofill_suggest({
            ...     "field": "email",
            ...     "context": "alice"
            ... })
            >>> print(result['suggestions'])
            ['alice@gmail.com', 'alice@company.com', 'alice@outlook.com']
            >>> 
            >>> # Phone suggestions
            >>> result = client.autofill_suggest({
            ...     "field": "phone",
            ...     "context": "555"
            ... })
            >>> print(result['suggestions'])
            ['555-0000', '555-1234', '555-5678']
        
        Notes:
            - Reduces boilerplate vs. generic post() call
            - Wraps POST to /autofill/suggest endpoint
            - Returns confidence score (0.0-1.0)
        """
        endpoint = "/autofill/suggest"
        return self.post(endpoint, payload=data)


# ============================================================================
# Integration Examples
# ============================================================================

if __name__ == '__main__':
    """
    Demonstration of APIClient usage patterns.
    """
    
    import os
    
    api_token = os.environ.get('API_TOKEN', 'sk-demo-token')
    client = APIClient(
        base_url="https://api.example.com",
        token=api_token,
        timeout=20
    )
    
    # Example 1: Threat Classification
    print("=== Threat Classification ===")
    try:
        result = client.post("threats/classify", {
            "text": "Click here to claim your free prize!",
            "model": "v2.1"
        })
        print(f"Label: {result['label']}, Confidence: {result['confidence']}")
    except Exception as e:
        print(f"Error: {e}\n")
    
    # Example 2: List Threats with Pagination
    print("=== List Threats ===")
    try:
        result = client.get("threats/list", params={"limit": 10, "type": "phishing"})
        print(f"Total: {result.get('total')}")
        for threat in result.get('threats', [])[:2]:
            print(f"  - {threat['id']}: {threat['type']}")
    except Exception as e:
        print(f"Error: {e}\n")
    
    # Example 3: Update Threat Status
    print("=== Update Threat ===")
    try:
        result = client.put("threats/12345", {
            "id": 12345,
            "status": "resolved",
            "resolved_by": "admin"
        })
        print(f"Status: {result.get('status')}")
    except Exception as e:
        print(f"Error: {e}\n")
    
    # Example 4: Autofill Suggestions
    print("=== Autofill ===")
    try:
        result = client.autofill_suggest({
            "field": "email",
            "context": "john.doe"
        })
        print(f"Suggestions: {result['suggestions']}")
        print(f"Confidence: {result['confidence']}")
    except Exception as e:
        print(f"Error: {e}\n")
    
    # Example 5: Compute Metrics
    print("=== Metrics ===")
    try:
        result = client.post("metrics/classification", {
            "y_true": [0, 1, 0, 1, 1],
            "y_pred": [0, 1, 0, 0, 1],
            "average": "weighted"
        })
        print(f"Precision: {result.get('precision'):.3f}")
        print(f"Recall: {result.get('recall'):.3f}")
        print(f"F1-Score: {result.get('f1'):.3f}")
    except Exception as e:
        print(f"Error: {e}")