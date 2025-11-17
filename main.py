from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any
import logging
from auth import verify_jwt, has_required_role

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Microsoft Entra ID JWT Auth API",
    description="A minimal FastAPI application with Microsoft Entra (Azure AD) JWT validation",
    version="1.0.0"
)

# CORS - allow both production and local development origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://sso-spike.onrender.com",  # Production frontend
        "http://localhost:5173",          # Local Vite dev server
        "http://localhost:3000",          # Alternative local port
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

# Simple request logger middleware to confirm requests reach backend
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Incoming request: {request.method} {request.url.path} from {request.client.host}")
    # Optionally log Authorization header presence (do not log token contents in prod)
    if "authorization" in request.headers:
        logger.info("Authorization header present")
    response = await call_next(request)
    logger.info(f"Response status: {response.status_code} for {request.method} {request.url.path}")
    return response

# Security scheme for Bearer token
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    try:
        claims = await verify_jwt(token)
        # Use preferred_username/email if available -- good for logs
        logger.info(f"Successfully authenticated user: {claims.get('preferred_username', 'unknown')}")
        return claims

    except Exception as e:
        logger.error(f"Token verification failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token validation failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def require_approver_role(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if not has_required_role(current_user, "approver"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: 'approver' role required"
        )
    return current_user

@app.get("/health")
async def health_check():
    return {"ok": True}

@app.get("/api/profile")
async def get_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Protected endpoint that decodes and returns the bearer token claims.
    Simply returns the raw JWT claims without any processing.
    """
    return current_user

@app.get("/api/admin-only")
async def admin_only_endpoint(current_user: Dict[str, Any] = Depends(require_approver_role)):
    return {
        "message": "Welcome to the admin area!",
        "user": {
            "email": current_user.get("email") or current_user.get("preferred_username"),
            "name": current_user.get("name"),
            "roles": current_user.get("roles", [])
        },
        "admin_info": {
            "access_level": "administrator",
            "permissions": ["read", "write", "delete", "approve"]
        }
    }

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception for {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
