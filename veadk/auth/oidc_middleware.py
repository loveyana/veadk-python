"""
OIDC Token Validation Middleware

This module provides middleware for validating OIDC tokens using multiple validation strategies:
1. Token introspection (preferred if client credentials available)
2. JWT validation with JWKS (fallback for JWT tokens)
"""

import time
from typing import Dict, List, Optional, Set

import httpx
from fastapi import HTTPException, Request, status

from veadk.utils.logger import get_logger

logger = get_logger(__name__)

# Try to import JWT libraries (optional dependency)
try:
    import jwt
    from jwt import PyJWKClient
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    logger.warning("JWT libraries not available. JWT validation will be disabled.")


class OIDCTokenValidator:
    """OIDC token validator using multiple validation strategies."""

    def __init__(
        self,
        discovery_url: str,
        allowed_clients: List[str],
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        cache_ttl: int = 300,   # Cache TTL in seconds
        timeout: int = 30,      # HTTP timeout in seconds
    ):
        """
        Initialize OIDC token validator with multiple validation strategies.

        Args:
            discovery_url: OpenID Connect discovery endpoint URL
            allowed_clients: List of allowed client IDs (audience values)
            client_id: Client ID for introspection endpoint authentication
            client_secret: Client secret for introspection endpoint authentication
            cache_ttl: Cache time-to-live for discovery document and validation results
            timeout: HTTP request timeout in seconds
        """
        self.discovery_url = discovery_url
        self.allowed_clients: Set[str] = set(allowed_clients)
        self.client_id = client_id
        self.client_secret = client_secret
        self.cache_ttl = cache_ttl
        self.timeout = timeout

        # Cache for discovery document and validation results
        self._discovery_cache: Optional[Dict] = None
        self._discovery_cache_time: float = 0
        self._introspection_cache: Dict[str, Dict] = {}  # token -> introspection result
        self._jwks_client: Optional[object] = None       # PyJWKClient instance
        self._jwks_cache_time: float = 0

        # HTTP client for requests
        self._http_client = httpx.AsyncClient(timeout=timeout)
    
    async def _get_discovery_document(self) -> Dict:
        """Get OpenID Connect discovery document with caching."""
        current_time = time.time()
        
        # Return cached document if still valid
        if (self._discovery_cache and 
            current_time - self._discovery_cache_time < self.cache_ttl):
            return self._discovery_cache
        
        logger.info(f"Fetching OIDC discovery document from: {self.discovery_url}")
        
        try:
            response = await self._http_client.get(self.discovery_url)
            response.raise_for_status()
            
            self._discovery_cache = response.json()
            self._discovery_cache_time = current_time
            
            logger.info("Successfully cached OIDC discovery document")
            return self._discovery_cache
            
        except httpx.RequestError as e:
            logger.error(f"Failed to fetch discovery document: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to fetch OIDC configuration"
            )
        except httpx.HTTPStatusError as e:
            logger.error(f"Discovery endpoint returned error: {e.response.status_code}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OIDC discovery endpoint unavailable"
            )
    
    async def _get_introspection_endpoint(self) -> Optional[str]:
        """Get introspection endpoint from discovery document."""
        discovery_doc = await self._get_discovery_document()
        return discovery_doc.get("introspection_endpoint")

    async def _get_jwks_uri(self) -> Optional[str]:
        """Get JWKS URI from discovery document."""
        discovery_doc = await self._get_discovery_document()
        return discovery_doc.get("jwks_uri")

    async def _get_issuer(self) -> Optional[str]:
        """Get issuer from discovery document."""
        discovery_doc = await self._get_discovery_document()
        return discovery_doc.get("issuer")
    
    async def _introspect_token(self, token: str) -> Dict:
        """
        Introspect token using OIDC introspection endpoint.

        Args:
            token: Token string to introspect

        Returns:
            Introspection response
        """
        # Check cache first
        current_time = time.time()
        if token in self._introspection_cache:
            cached_result = self._introspection_cache[token]
            # Check if cached result is still valid (not expired)
            if cached_result.get("exp", 0) > current_time:
                logger.debug("Using cached introspection result")
                return cached_result
            else:
                # Remove expired cache entry
                del self._introspection_cache[token]

        # Get introspection endpoint
        introspection_endpoint = await self._get_introspection_endpoint()

        # Prepare introspection request
        data = {"token": token}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        # Add client authentication if provided
        auth = None
        if self.client_id and self.client_secret:
            auth = (self.client_id, self.client_secret)

        logger.debug(f"Introspecting token at: {introspection_endpoint}")

        try:
            response = await self._http_client.post(
                introspection_endpoint,
                data=data,
                headers=headers,
                auth=auth
            )
            response.raise_for_status()

            introspection_result = response.json()

            # Cache the result if token is active
            if introspection_result.get("active", False):
                self._introspection_cache[token] = introspection_result

                # Clean up expired cache entries periodically
                if len(self._introspection_cache) > 1000:  # Prevent memory leak
                    self._cleanup_cache()

            return introspection_result

        except httpx.RequestError as e:
            logger.error(f"Failed to introspect token: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to validate token"
            )
        except httpx.HTTPStatusError as e:
            logger.error(f"Introspection endpoint returned error: {e.response.status_code}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Token validation service unavailable"
            )

    def _cleanup_cache(self):
        """Clean up expired cache entries."""
        current_time = time.time()
        expired_tokens = [
            token for token, result in self._introspection_cache.items()
            if result.get("exp", 0) <= current_time
        ]
        for token in expired_tokens:
            del self._introspection_cache[token]
        logger.debug(f"Cleaned up {len(expired_tokens)} expired cache entries")

    async def _get_jwks_client(self):
        """Get JWKS client for JWT validation."""
        if not JWT_AVAILABLE:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="JWT validation not available (missing dependencies)"
            )

        current_time = time.time()

        # Return cached client if still valid
        if (self._jwks_client and
            current_time - self._jwks_cache_time < self.cache_ttl):
            return self._jwks_client

        jwks_uri = await self._get_jwks_uri()
        if not jwks_uri:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="No jwks_uri found in discovery document"
            )

        logger.info(f"Creating JWKS client for: {jwks_uri}")

        self._jwks_client = PyJWKClient(
            jwks_uri,
            lifespan=self.cache_ttl,
            timeout=self.timeout
        )
        self._jwks_cache_time = current_time

        return self._jwks_client

    async def _validate_with_jwt(self, token: str) -> Dict:
        """
        Validate JWT token using JWKS.

        Args:
            token: JWT token to validate

        Returns:
            Decoded JWT payload with validation metadata
        """
        if not JWT_AVAILABLE:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="JWT validation not available (missing dependencies)"
            )

        try:
            # Get JWKS client
            jwks_client = await self._get_jwks_client()

            # Get issuer for validation
            expected_issuer = await self._get_issuer()

            # Get signing key
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            print(self.allowed_clients)
            # Decode and validate token
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256", "HS256"],  # Common OIDC algorithms
                audience=list(self.allowed_clients) if self.allowed_clients else None,
                issuer=expected_issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": bool(self.allowed_clients),
                    "verify_iss": bool(expected_issuer),
                }
            )

            # Add validation metadata
            payload.update({
                "active": True,
                "_validation_method": "jwt"
            })

            logger.debug(f"Successfully validated JWT for subject: {payload.get('sub')}")
            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.InvalidAudienceError:
            logger.warning("JWT audience validation failed")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token audience not authorized"
            )
        except jwt.InvalidIssuerError:
            logger.warning("JWT issuer validation failed")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token issuer not trusted"
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT validation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        except Exception as e:
            logger.error(f"Unexpected error during JWT validation: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="JWT validation error"
            )

    async def validate_token(self, token: str) -> Dict:
        """
        Validate token using multiple strategies in order of preference:
        1. Token introspection (if client credentials available)
        2. UserInfo endpoint (for access tokens)
        3. JWT validation with JWKS (for JWT tokens)

        Args:
            token: Token string to validate

        Returns:
            Token validation result

        Raises:
            HTTPException: If token is invalid or validation fails
        """
        validation_errors = []

        # Strategy 1: Try introspection if client credentials are available
        if self.client_id and self.client_secret:
            try:
                introspection_endpoint = await self._get_introspection_endpoint()
                if introspection_endpoint:
                    logger.debug("Attempting token validation via introspection")
                    result = await self._introspect_token(token)

                    # Validate introspection result
                    if not result.get("active", False):
                        raise HTTPException(status_code=401, detail="Token is not active")

                    exp = result.get("exp")
                    if exp and exp <= time.time():
                        raise HTTPException(status_code=401, detail="Token has expired")

                    # Check client authorization
                    if not self._check_client_authorization(result):
                        raise HTTPException(status_code=403, detail="Token client not authorized")

                    logger.debug(f"Successfully validated token via introspection for subject: {result.get('sub')}")
                    return result
                else:
                    logger.debug("No introspection endpoint available")
            except HTTPException:
                raise  # Re-raise HTTP exceptions (auth failures)
            except Exception as e:
                validation_errors.append(f"Introspection failed: {e}")
                logger.warning(f"Introspection validation failed: {e}")

        # Strategy 2: Try JWT validation
        try:
            jwks_uri = await self._get_jwks_uri()
            if jwks_uri and JWT_AVAILABLE:
                logger.debug("Attempting token validation via JWT")
                result = await self._validate_with_jwt(token)

                # JWT validation already checks audience, but double-check client authorization
                if not self._check_client_authorization(result):
                    raise HTTPException(status_code=403, detail="Token client not authorized")

                logger.debug(f"Successfully validated token via JWT for subject: {result.get('sub')}")
                return result
            else:
                if not jwks_uri:
                    logger.debug("No JWKS URI available")
                if not JWT_AVAILABLE:
                    logger.debug("JWT libraries not available")
        except HTTPException:
            raise  # Re-raise HTTP exceptions (auth failures)
        except Exception as e:
            validation_errors.append(f"JWT validation failed: {e}")
            logger.warning(f"JWT validation failed: {e}")

        # If all strategies failed, raise an error
        error_summary = "; ".join(validation_errors) if validation_errors else "No validation methods available"
        logger.error(f"All token validation strategies failed: {error_summary}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Unable to validate token: {error_summary}"
        )

    def _check_client_authorization(self, token_data: Dict) -> bool:
        """Check if token client/audience is authorized."""
        if not self.allowed_clients:
            return True  # No restrictions

        # Check client_id
        client_id = token_data.get("client_id") or token_data.get("azp")
        if client_id and client_id in self.allowed_clients:
            return True

        # Check audience
        aud = token_data.get("aud")
        if aud:
            audiences = aud if isinstance(aud, list) else [aud]
            if any(audience in self.allowed_clients for audience in audiences):
                return True

        return False
    
    async def close(self):
        """Close HTTP client."""
        await self._http_client.aclose()


def create_oidc_middleware(
    discovery_url: str,
    allowed_clients: List[str],
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    excluded_paths: Optional[List[str]] = None,
    cache_ttl: int = 300,
    timeout: int = 30,
):
    """
    Create OIDC token validation middleware with multiple validation strategies.

    The middleware attempts validation in the following order:
    1. Token introspection (if client_id/client_secret provided)
    2. JWT validation with JWKS (for JWT tokens)

    Args:
        discovery_url: OpenID Connect discovery endpoint URL
        allowed_clients: List of allowed client IDs (audience values)
        client_id: Optional client ID for introspection endpoint authentication
        client_secret: Optional client secret for introspection endpoint authentication
        excluded_paths: List of paths to exclude from validation
        cache_ttl: Cache TTL for discovery document and validation results
        timeout: HTTP request timeout

    Returns:
        FastAPI middleware function
    """
    validator = OIDCTokenValidator(
        discovery_url=discovery_url,
        allowed_clients=allowed_clients,
        client_id=client_id,
        client_secret=client_secret,
        cache_ttl=cache_ttl,
        timeout=timeout,
    )
    
    excluded_paths = excluded_paths or []
    excluded_paths_set = set(excluded_paths)
    
    async def oidc_middleware(request: Request, call_next):
        """OIDC token validation middleware."""
        
        # Skip validation for excluded paths
        if request.url.path in excluded_paths_set:
            return await call_next(request)
        
        # Extract bearer token from Authorization header
        authorization = request.headers.get("Authorization")
        if not authorization:
            logger.warning(f"No Authorization header for path: {request.url.path}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header required"
            )
        
        if not authorization.startswith("Bearer "):
            logger.warning(f"Invalid Authorization header format for path: {request.url.path}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer token required"
            )
        
        token = authorization[7:]  # Remove "Bearer " prefix
        
        # Validate token
        try:
            payload = await validator.validate_token(token)
            
            # Add token payload to request state for downstream use
            request.state.oidc_token = payload
            request.state.user_id = payload.get("sub")
            request.state.client_id = payload.get("client_id") or payload.get("azp")
            
            logger.debug(f"OIDC validation successful for user: {payload.get('sub')}")
            
        except HTTPException:
            # Re-raise HTTP exceptions from validator
            raise
        except Exception as e:
            logger.error(f"Unexpected error in OIDC middleware: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication service error"
            )
        
        return await call_next(request)
    
    return oidc_middleware
