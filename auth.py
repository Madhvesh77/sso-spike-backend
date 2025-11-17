import os
import json
from typing import Dict, Any, Optional
from cachetools import TTLCache
from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError, JWTClaimsError
import httpx
import asyncio

# Cache for storing JWKS keys (Time-To-Live cache with 1 hour expiration)
jwks_cache = TTLCache(maxsize=1, ttl=3600)

async def fetch_jwks(tenant_id: str) -> Dict[str, Any]:
    """
    Fetch JWKS (JSON Web Key Set) from Microsoft Entra ID discovery endpoint.
    
    Args:
        tenant_id: The Azure AD tenant ID
        
    Returns:
        Dictionary containing the JWKS
    """
    jwks_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
    
    # Check cache first
    if "jwks" in jwks_cache:
        return jwks_cache["jwks"]
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(jwks_url)
            response.raise_for_status()
            jwks = response.json()
            
            # Cache the JWKS for 1 hour
            jwks_cache["jwks"] = jwks
            return jwks
            
        except httpx.HTTPError as e:
            raise Exception(f"Failed to fetch JWKS: {str(e)}")

def get_signing_key(jwks: Dict[str, Any], kid: str) -> Optional[str]:
    """
    Extract the signing key from JWKS for a given key ID.
    
    Args:
        jwks: The JSON Web Key Set
        kid: Key ID from the JWT header
        
    Returns:
        The signing key or None if not found
    """
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            # Return the key in PEM format for RSA keys
            if key.get("kty") == "RSA":
                return key
    return None

async def verify_jwt(token: str) -> Dict[str, Any]:
    """
    Verify and decode a JWT token from Microsoft Entra ID.
    
    Args:
        token: The JWT token to verify
        
    Returns:
        Decoded JWT claims
        
    Raises:
        Exception: If token is invalid, expired, or verification fails
    """
    # Get configuration from environment variables
    tenant_id = os.getenv("TENANT_ID")
    api_audience = os.getenv("API_AUDIENCE") or os.getenv("CLIENT_ID")
    
    if not tenant_id:
        raise Exception("TENANT_ID environment variable is required")
    
    if not api_audience:
        raise Exception("API_AUDIENCE (or CLIENT_ID) environment variable is required")
    
    try:
        # Decode the token header to get the key ID
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        if not kid:
            raise Exception("Token header missing 'kid' (Key ID)")
        
        # Fetch JWKS from Microsoft
        jwks = await fetch_jwks(tenant_id)
        
        # Get the signing key
        signing_key = get_signing_key(jwks, kid)
        if not signing_key:
            raise Exception(f"Signing key not found for kid: {kid}")
        
        # Verify and decode the token
        # Expected issuer for Azure AD v2.0 tokens
        expected_issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        
        decoded_token = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=api_audience,
            issuer=expected_issuer,
            options={
                "verify_signature": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "require_aud": True,
                "require_iss": True,
                "require_exp": True
            }
        )
        
        return decoded_token
        
    except ExpiredSignatureError:
        raise Exception("Token has expired")
    except JWTClaimsError as e:
        raise Exception(f"Token claims validation failed: {str(e)}")
    except JWTError as e:
        raise Exception(f"Token validation failed: {str(e)}")
    except Exception as e:
        raise Exception(f"Token verification error: {str(e)}")

def has_required_role(claims: Dict[str, Any], required_role: str) -> bool:
    """
    Check if the user has a required role in their JWT claims.
    
    Args:
        claims: Decoded JWT claims
        required_role: The role to check for
        
    Returns:
        True if user has the required role, False otherwise
    """
    # Roles can be in different claim types depending on token type
    roles = claims.get("roles", [])  # App roles
    if not roles:
        roles = claims.get("groups", [])  # Group memberships
    
    return required_role in roles if roles else False