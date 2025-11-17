# FastAPI Microsoft Entra ID JWT Authentication

A minimal FastAPI application that validates Microsoft Entra (Azure AD) access tokens using JWKS (JSON Web Key Set).

## Features

- JWT token validation using Microsoft Entra ID JWKS
- JWKS caching for improved performance
- Role-based access control
- Three endpoints:
  - `/health` - Public health check
  - `/api/profile` - Protected profile endpoint (requires valid JWT)
  - `/api/admin-only` - Admin endpoint (requires "approver" role)

## Prerequisites

- Python 3.8+
- Microsoft Entra ID (Azure AD) tenant
- Registered application in Azure AD

## Environment Variables

You need to set the following environment variables:

### Required Variables

1. **TENANT_ID**: Your Azure AD tenant ID

   - Find this in Azure Portal → Azure Active Directory → Overview → Tenant ID
   - Example: `12345678-1234-1234-1234-123456789012`

2. **API_AUDIENCE** (or **CLIENT_ID**): Your application's client ID or audience
   - Find this in Azure Portal → App registrations → Your App → Overview → Application (client) ID
   - Example: `87654321-4321-4321-4321-210987654321`

### Setting Environment Variables

#### Option 1: Export in terminal (temporary)

```bash
export TENANT_ID="your-tenant-id-here"
export API_AUDIENCE="your-client-id-here"
```

#### Option 2: Create .env file (recommended)

Create a `.env` file in the project root:

```bash
TENANT_ID=your-tenant-id-here
API_AUDIENCE=your-client-id-here
```

Then install python-dotenv and load it in your application:

```bash
pip install python-dotenv
```

## Installation

1. **Clone or create the project directory**

2. **Install dependencies**:

   ```bash
   pip install fastapi uvicorn python-jose[cryptography] httpx cachetools
   ```

3. **Set environment variables** (see above)

4. **Run the application**:
   ```bash
   uvicorn main:app --reload
   ```

The API will be available at `http://localhost:8000`

## API Documentation

Once running, visit:

- **Interactive API docs**: `http://localhost:8000/docs`
- **ReDoc documentation**: `http://localhost:8000/redoc`

## Endpoints

### 1. Health Check (Public)

```bash
GET /health
```

Returns: `{"ok": true}`

### 2. User Profile (Protected)

```bash
GET /api/profile
Authorization: Bearer <your-jwt-token>
```

Returns user profile information from JWT claims.

### 3. Admin Only (Role-Protected)

```bash
GET /api/admin-only
Authorization: Bearer <your-jwt-token>
```

Requires "approver" role in JWT token.

## Testing with JWT Tokens

### Getting a JWT Token

1. **From Azure AD**: Use Azure CLI, PowerShell, or your application's login flow
2. **For testing**: You can use tools like Postman with Azure AD OAuth2 flow

### Example using curl

```bash
# Health check (no auth required)
curl http://localhost:8000/health

# Profile endpoint (requires JWT)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8000/api/profile

# Admin endpoint (requires JWT with "approver" role)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8000/api/admin-only
```

## File Structure

- `auth.py` - JWT verification logic and JWKS handling
- `main.py` - FastAPI application with endpoints and middleware
- `README.md` - This documentation

## Configuration Details

### Azure AD App Registration

Your Azure AD application should be configured with:

1. **Authentication**: Configure redirect URIs if using interactive flows
2. **API permissions**: Grant necessary Microsoft Graph permissions if needed
3. **App roles** (optional): Define custom roles like "approver" for role-based access
4. **Token configuration**: Ensure proper claims are included in tokens

### JWT Token Claims

The application expects standard Azure AD v2.0 token claims:

- `sub`: Subject (user ID)
- `aud`: Audience (should match your API_AUDIENCE)
- `iss`: Issuer (Azure AD)
- `exp`: Expiration time
- `roles`: Array of assigned roles (for role-based access)
- `preferred_username`: User's email/username
- `name`: User's display name

## Security Features

- **Token signature verification** using RSA256 and JWKS
- **Token expiration validation**
- **Audience and issuer validation**
- **JWKS caching** (1 hour TTL) for performance
- **Role-based access control**
- **Comprehensive error handling**

## Troubleshooting

### Common Issues

1. **"TENANT_ID environment variable is required"**

   - Set the TENANT_ID environment variable

2. **"API_AUDIENCE environment variable is required"**

   - Set either API_AUDIENCE or CLIENT_ID environment variable

3. **"Token validation failed"**

   - Check that your JWT token is valid and not expired
   - Verify TENANT_ID and API_AUDIENCE match your Azure AD configuration

4. **"Access denied: 'approver' role required"**
   - User needs "approver" role assigned in Azure AD
   - Check App roles configuration in Azure Portal

### Logs

The application logs authentication events. Check console output for detailed error messages.

## Development

To run in development mode with auto-reload:

```bash
uvicorn main:app --reload --log-level debug
```

## Production Considerations

- Use environment variables or secure configuration management
- Enable HTTPS in production
- Consider rate limiting and additional security middleware
- Monitor and log security events
- Regular security updates for dependencies
