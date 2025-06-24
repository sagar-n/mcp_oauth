# #!/usr/bin/env python3
# """
# OAuth MCP Server
# Implements OAuth 2.1 with proper MCP integration using FastMCP
# """

# from fastapi import FastAPI, HTTPException, Depends, status, Request, Query
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.responses import RedirectResponse
# from pydantic import BaseModel
# from typing import Optional, Dict, Any
# from datetime import datetime, timedelta, timezone
# import jwt
# import uvicorn
# import secrets
# import time
# from urllib.parse import urlencode, parse_qs

# # OAuth configuration
# SECRET_KEY = "sagar-test"  # In production, use environment variable
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# # Create FastAPI app
# app = FastAPI()

# # Enable CORS
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # OAuth models
# class Token(BaseModel):
#     access_token: str
#     token_type: str
#     expires_in: Optional[int] = None

# class ClientRegistration(BaseModel):
#     client_name: str
#     redirect_uris: list[str]
#     token_endpoint_auth_method: str = "client_secret_post"
#     grant_types: list[str] = ["authorization_code", "refresh_token"]
#     response_types: list[str] = ["code"]
#     scope: str = "read write"

# class ClientInfo(BaseModel):
#     client_id: str
#     client_secret: str
#     client_id_issued_at: int
#     client_secret_expires_at: int
#     redirect_uris: list[str]
#     grant_types: list[str]
#     token_endpoint_auth_method: str
#     scope: str

# # Demo databases
# users_db = {
#     "demo": {
#         "username": "demo",
#         "password": "demo123",
#         "disabled": False
#     }
# }

# clients_db = {}
# auth_codes = {}
# access_tokens = {}

# # Security scheme
# security = HTTPBearer()

# # OAuth helper functions
# def create_access_token(data: dict):
#     to_encode = data.copy()
#     expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt

# def verify_token(token: str):
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             return None
#         return {"username": username, "client_id": payload.get("client_id")}
#     except jwt.PyJWTError:
#         return None

# # Store user context for MCP tools
# current_user_context = {}

# # OAuth endpoints
# @app.get("/.well-known/oauth-authorization-server")
# async def oauth_metadata():
#     return {
#         "issuer": "http://localhost:9000",
#         "authorization_endpoint": "http://localhost:9000/oauth/authorize",
#         "token_endpoint": "http://localhost:9000/oauth/token",
#         "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
#         "grant_types_supported": ["authorization_code", "refresh_token"],
#         "response_types_supported": ["code"],
#         "scopes_supported": ["read", "write"],
#         "registration_endpoint": "http://localhost:9000/oauth/register"
#     }

# @app.post("/oauth/register", response_model=ClientInfo)
# async def register_client(client: ClientRegistration):
#     """Register a new OAuth client"""
#     client_id = secrets.token_urlsafe(32)
#     client_secret = secrets.token_urlsafe(32)
#     now = int(time.time())
    
#     client_info = ClientInfo(
#         client_id=client_id,
#         client_secret=client_secret,
#         client_id_issued_at=now,
#         client_secret_expires_at=0,  # Never expires
#         redirect_uris=client.redirect_uris,
#         grant_types=client.grant_types,
#         token_endpoint_auth_method=client.token_endpoint_auth_method,
#         scope=client.scope
#     )
    
#     clients_db[client_id] = client_info
#     print(f"Registered client: {client_id}")
#     return client_info

# @app.get("/oauth/authorize")
# async def authorize(
#     response_type: str = Query(...),
#     client_id: str = Query(...),
#     redirect_uri: str = Query(...),
#     state: Optional[str] = Query(None),
#     code_challenge: Optional[str] = Query(None),
#     code_challenge_method: Optional[str] = Query(None),
#     scope: Optional[str] = Query(None)
# ):
#     """OAuth 2.1 authorization endpoint"""
#     print(f"Authorization request for client: {client_id}")
    
#     # Validate client
#     client = clients_db.get(client_id)
#     if not client:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Invalid client_id"
#         )
    
#     # Validate redirect URI
#     if redirect_uri not in client.redirect_uris:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Invalid redirect_uri"
#         )
    
#     # Validate response type
#     if response_type != "code":
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Invalid response_type"
#         )
    
#     # Generate authorization code
#     auth_code = secrets.token_urlsafe(32)
    
#     # Store authorization code with associated data
#     auth_codes[auth_code] = {
#         "client_id": client_id,
#         "redirect_uri": redirect_uri,
#         "scope": scope or "read write",
#         "code_challenge": code_challenge,
#         "code_challenge_method": code_challenge_method,
#         "expires_at": int(time.time()) + 600,  # 10 minutes expiry
#         "user": "demo"  # For demo purposes, auto-approve
#     }
    
#     print(f"Generated auth code: {auth_code}")
    
#     # Build redirect URI with authorization code
#     params = {"code": auth_code}
#     if state:
#         params["state"] = state
        
#     redirect_url = f"{redirect_uri}?{urlencode(params)}"
#     print(f"Redirecting to: {redirect_url}")
    
#     return RedirectResponse(url=redirect_url)

# @app.post("/oauth/token", response_model=Token)
# async def token_exchange(request: Request):
#     """OAuth 2.1 token endpoint"""
#     # Parse form data
#     form_data = await request.form()
    
#     grant_type = form_data.get("grant_type")
#     code = form_data.get("code")
#     redirect_uri = form_data.get("redirect_uri")
#     client_id = form_data.get("client_id")
#     client_secret = form_data.get("client_secret")
    
#     print(f"Token exchange request: grant_type={grant_type}, client_id={client_id}")
    
#     if grant_type != "authorization_code":
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Unsupported grant type"
#         )
    
#     if not code:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Missing authorization code"
#         )
    
#     # Validate authorization code
#     auth_data = auth_codes.get(code)
#     if not auth_data:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Invalid authorization code"
#         )
    
#     # Check if code is expired
#     if int(time.time()) > auth_data["expires_at"]:
#         del auth_codes[code]
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Authorization code expired"
#         )
    
#     # Validate client
#     client = clients_db.get(auth_data["client_id"])
#     if not client:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Invalid client"
#         )
    
#     # Validate client credentials
#     if client_id != auth_data["client_id"] or client_secret != client.client_secret:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid client credentials"
#         )
    
#     # Validate redirect URI
#     if redirect_uri != auth_data["redirect_uri"]:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Invalid redirect URI"
#         )
    
#     # Generate access token
#     access_token = create_access_token(data={
#         "sub": auth_data["user"],
#         "client_id": client_id,
#         "scope": auth_data["scope"]
#     })
    
#     # Clean up used authorization code
#     del auth_codes[code]
    
#     print(f"Issued access token for user: {auth_data['user']}")
    
#     return {
#         "access_token": access_token,
#         "token_type": "bearer",
#         "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
#     }

# # Middleware to inject OAuth context into MCP requests
# @app.middleware("http")
# async def oauth_context_middleware(request: Request, call_next):
#     print(f"🔍 Processing request: {request.method} {request.url.path}")
    
#     # Only apply to MCP endpoints
#     if request.url.path.startswith("/mcp"):
#         print("MCP endpoint detected, checking authentication...")
        
#         # Extract and verify OAuth token
#         auth_header = request.headers.get("Authorization")
#         print(f"Auth header: {auth_header[:50] if auth_header else 'None'}...")
        
#         if auth_header and auth_header.startswith("Bearer "):
#             token = auth_header.split(" ")[1]
#             user_data = verify_token(token)
#             if user_data:
#                 # Store user context globally for MCP tools to access
#                 current_user_context.update(user_data)
#                 print(f"🔑 Authenticated request from user: {user_data['username']}")
#             else:
#                 print("Invalid token in request")
#                 from fastapi.responses import JSONResponse
#                 return JSONResponse(
#                     status_code=status.HTTP_401_UNAUTHORIZED,
#                     content={"detail": "Invalid token"}
#                 )
#         else:
#             print("Missing Authorization header")
#             from fastapi.responses import JSONResponse
#             return JSONResponse(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 content={"detail": "Missing authorization header"}
#             )
    
#     try:
#         response = await call_next(request)
#         print(f"Request completed with status: {response.status_code}")
#         return response
#     except Exception as e:
#         print(f"Error processing request: {e}")
#         from fastapi.responses import JSONResponse
#         return JSONResponse(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             content={"detail": f"Internal server error: {str(e)}"}
#         )

# # Instead of mounting FastMCP, let's create proper MCP endpoints
# @app.post("/mcp")
# async def handle_mcp_request(request: Request):
#     """Handle MCP requests directly"""
#     try:
#         # The middleware has already verified authentication and set current_user_context
#         body = await request.json()
        
#         # Handle MCP protocol messages
#         jsonrpc_version = body.get("jsonrpc", "2.0")
#         method = body.get("method")
#         params = body.get("params", {})
#         request_id = body.get("id")
        
#         print(f"🔧 MCP Request: {method}")
        
#         if method == "initialize":
#             return {
#                 "jsonrpc": jsonrpc_version,
#                 "id": request_id,
#                 "result": {
#                     "protocolVersion": "2024-11-05",
#                     "capabilities": {
#                         "tools": {}
#                     },
#                     "serverInfo": {
#                         "name": "OAuth MCP Server",
#                         "version": "1.0.0"
#                     }
#                 }
#             }
        
#         elif method == "tools/list":
#             return {
#                 "jsonrpc": jsonrpc_version,
#                 "id": request_id,
#                 "result": {
#                     "tools": [
#                         {
#                             "name": "echo",
#                             "description": "Echo back the provided text",
#                             "inputSchema": {
#                                 "type": "object",
#                                 "properties": {
#                                     "text": {"type": "string", "description": "Text to echo back"}
#                                 },
#                                 "required": ["text"]
#                             }
#                         },
#                         {
#                             "name": "get_time",
#                             "description": "Get current server time",
#                             "inputSchema": {
#                                 "type": "object",
#                                 "properties": {}
#                             }
#                         },
#                         {
#                             "name": "get_user_info",
#                             "description": "Get current user information",
#                             "inputSchema": {
#                                 "type": "object",
#                                 "properties": {}
#                             }
#                         }
#                     ]
#                 }
#             }
        
#         elif method == "tools/call":
#             tool_name = params.get("name")
#             arguments = params.get("arguments", {})
            
#             # Get user context from middleware
#             username = current_user_context.get("username", "unknown")
#             client_id = current_user_context.get("client_id", "unknown")
            
#             if tool_name == "echo":
#                 text = arguments.get("text", "")
#                 result_text = f"Echo from {username}: {text}"
#             elif tool_name == "get_time":
#                 result_text = f"Server time for {username}: {datetime.now().isoformat()}"
#             elif tool_name == "get_user_info":
#                 result_text = f"Current user: {username}, Client ID: {client_id}"
#             else:
#                 return {
#                     "jsonrpc": jsonrpc_version,
#                     "id": request_id,
#                     "error": {
#                         "code": -32601,
#                         "message": f"Unknown tool: {tool_name}"
#                     }
#                 }
            
#             return {
#                 "jsonrpc": jsonrpc_version,
#                 "id": request_id,
#                 "result": {
#                     "content": [
#                         {
#                             "type": "text",
#                             "text": result_text
#                         }
#                     ]
#                 }
#             }
        
#         elif method == "notifications/initialized":
#             # This is a notification, no response needed
#             print("MCP client initialized")
#             return None
        
#         else:
#             return {
#                 "jsonrpc": jsonrpc_version,
#                 "id": request_id,
#                 "error": {
#                     "code": -32601,
#                     "message": f"Unknown method: {method}"
#                 }
#             }
    
#     except Exception as e:
#         print(f"❌ Error handling MCP request: {e}")
#         return {
#             "jsonrpc": "2.0",
#             "id": request_id if 'request_id' in locals() else None,
#             "error": {
#                 "code": -32603,
#                 "message": f"Internal error: {str(e)}"
#             }
#         }

# # Health check endpoint
# @app.get("/health")
# async def health_check():
#     return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# if __name__ == "__main__":
#     print("Starting OAuth MCP Server on http://localhost:9000")
#     print("OAuth metadata available at: http://localhost:9000/.well-known/oauth-authorization-server")
#     print("MCP endpoint available at: http://localhost:9000/mcp")
#     uvicorn.run(app, host="0.0.0.0", port=9000)

#!/usr/bin/env python3
"""
OAuth MCP Server
Implements OAuth 2.1 with proper MCP integration using FastMCP
"""

from fastapi import FastAPI, HTTPException, Depends, status, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone
import jwt
import uvicorn
import secrets
import time
from urllib.parse import urlencode, parse_qs
import hashlib
import base64

# OAuth configuration
SECRET_KEY = "sagar-test"  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Create FastAPI app
app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth models
class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: Optional[int] = None

class ClientRegistration(BaseModel):
    client_name: str
    redirect_uris: list[str]
    token_endpoint_auth_method: str = "client_secret_post"
    grant_types: list[str] = ["authorization_code", "refresh_token"]
    response_types: list[str] = ["code"]
    scope: str = "read write"

class ClientInfo(BaseModel):
    client_id: str
    client_secret: str
    client_id_issued_at: int
    client_secret_expires_at: int
    redirect_uris: list[str]
    grant_types: list[str]
    token_endpoint_auth_method: str
    scope: str

# Demo databases
users_db = {
    "demo": {
        "username": "demo",
        "password": "demo123",
        "disabled": False
    }
}

clients_db = {}
auth_codes = {}
access_tokens = {}

# Security scheme
security = HTTPBearer()

# OAuth helper functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return {"username": username, "client_id": payload.get("client_id")}
    except jwt.PyJWTError:
        return None

def verify_code_challenge(code_verifier: str, code_challenge: str, method: str) -> bool:
    """Verify PKCE code challenge"""
    if method == "S256":
        # Create SHA256 hash of code_verifier
        digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        # Base64 URL encode (without padding)
        computed_challenge = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
        return computed_challenge == code_challenge
    elif method == "plain":
        return code_verifier == code_challenge
    else:
        return False

# Store user context for MCP tools
current_user_context = {}

# OAuth endpoints
@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    return {
        "issuer": "http://localhost:9000",
        "authorization_endpoint": "http://localhost:9000/oauth/authorize",
        "token_endpoint": "http://localhost:9000/oauth/token",
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_types_supported": ["code"],
        "scopes_supported": ["read", "write"],
        "registration_endpoint": "http://localhost:9000/oauth/register",
        "code_challenge_methods_supported": ["S256", "plain"]
    }

@app.post("/oauth/register", response_model=ClientInfo)
async def register_client(client: ClientRegistration):
    """Register a new OAuth client"""
    client_id = secrets.token_urlsafe(32)
    client_secret = secrets.token_urlsafe(32)
    now = int(time.time())
    
    client_info = ClientInfo(
        client_id=client_id,
        client_secret=client_secret,
        client_id_issued_at=now,
        client_secret_expires_at=0,  # Never expires
        redirect_uris=client.redirect_uris,
        grant_types=client.grant_types,
        token_endpoint_auth_method=client.token_endpoint_auth_method,
        scope=client.scope
    )
    
    clients_db[client_id] = client_info
    print(f"Registered client: {client_id}")
    return client_info

@app.get("/oauth/authorize")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    state: Optional[str] = Query(None),
    code_challenge: Optional[str] = Query(None),
    code_challenge_method: Optional[str] = Query(None),
    scope: Optional[str] = Query(None)
):
    """OAuth 2.1 authorization endpoint with PKCE support"""
    print(f"Authorization request for client: {client_id}")
    print(f"PKCE parameters: challenge={code_challenge[:10] if code_challenge else None}..., method={code_challenge_method}")
    
    # Validate client
    client = clients_db.get(client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid client_id"
        )
    
    # Validate redirect URI
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid redirect_uri"
        )
    
    # Validate response type
    if response_type != "code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid response_type"
        )
    
    # Validate PKCE parameters if provided
    if code_challenge:
        if code_challenge_method not in ["S256", "plain"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported code challenge method. Supported: S256, plain"
            )
        
        # Validate code challenge format
        if code_challenge_method == "S256":
            # S256 challenges should be base64url encoded (43-128 chars)
            if not (43 <= len(code_challenge) <= 128):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid code challenge length for S256"
                )
        
        print(f"✅ PKCE validation passed: method={code_challenge_method}")
    
    # Generate authorization code
    auth_code = secrets.token_urlsafe(32)
    
    # Store authorization code with associated data
    auth_codes[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope or "read write",
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": int(time.time()) + 600,  # 10 minutes expiry
        "user": "demo"  # For demo purposes, auto-approve
    }
    
    print(f"Generated auth code: {auth_code}")
    
    # Build redirect URI with authorization code
    params = {"code": auth_code}
    if state:
        params["state"] = state
        
    redirect_url = f"{redirect_uri}?{urlencode(params)}"
    print(f"Redirecting to: {redirect_url}")
    
    return RedirectResponse(url=redirect_url)

@app.post("/oauth/token", response_model=Token)
async def token_exchange(request: Request):
    """OAuth 2.1 token endpoint with PKCE support"""
    # Parse form data
    form_data = await request.form()
    
    grant_type = form_data.get("grant_type")
    code = form_data.get("code")
    redirect_uri = form_data.get("redirect_uri")
    client_id = form_data.get("client_id")
    client_secret = form_data.get("client_secret")
    code_verifier = form_data.get("code_verifier")  # PKCE code verifier
    
    print(f"Token exchange request: grant_type={grant_type}, client_id={client_id}, has_code_verifier={bool(code_verifier)}")
    
    if grant_type != "authorization_code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported grant type"
        )
    
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing authorization code"
        )
    
    # Validate authorization code
    auth_data = auth_codes.get(code)
    if not auth_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authorization code"
        )
    
    # Check if code is expired
    if int(time.time()) > auth_data["expires_at"]:
        del auth_codes[code]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code expired"
        )
    
    # Validate client
    client = clients_db.get(auth_data["client_id"])
    if not client:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid client"
        )
    
    # Validate client credentials
    if client_id != auth_data["client_id"] or client_secret != client.client_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials"
        )
    
    # Validate redirect URI
    if redirect_uri != auth_data["redirect_uri"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid redirect URI"
        )
    
    # Validate PKCE if used
    if auth_data.get("code_challenge"):
        if not code_verifier:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing code verifier for PKCE"
            )
        
        code_challenge = auth_data["code_challenge"]
        code_challenge_method = auth_data.get("code_challenge_method", "S256")
        
        if not verify_code_challenge(code_verifier, code_challenge, code_challenge_method):
            print(f"❌ PKCE verification failed: verifier={code_verifier[:10]}..., challenge={code_challenge[:10]}..., method={code_challenge_method}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid code verifier"
            )
        
        print(f"✅ PKCE verification successful")
    
    # Generate access token
    access_token = create_access_token(data={
        "sub": auth_data["user"],
        "client_id": client_id,
        "scope": auth_data["scope"]
    })
    
    # Clean up used authorization code
    del auth_codes[code]
    
    print(f"Issued access token for user: {auth_data['user']}")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

# Middleware to inject OAuth context into MCP requests
@app.middleware("http")
async def oauth_context_middleware(request: Request, call_next):
    print(f"🔍 Processing request: {request.method} {request.url.path}")
    
    # Only apply to MCP endpoints
    if request.url.path.startswith("/mcp"):
        print("🎯 MCP endpoint detected, checking authentication...")
        
        # Extract and verify OAuth token
        auth_header = request.headers.get("Authorization")
        print(f"🔍 Auth header: {auth_header[:50] if auth_header else 'None'}...")
        
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            user_data = verify_token(token)
            if user_data:
                # Store user context globally for MCP tools to access
                current_user_context.update(user_data)
                print(f"🔑 Authenticated request from user: {user_data['username']}")
            else:
                print("❌ Invalid token in request")
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid token"}
                )
        else:
            print("❌ Missing Authorization header")
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing authorization header"}
            )
    
    try:
        response = await call_next(request)
        print(f"✅ Request completed with status: {response.status_code}")
        return response
    except Exception as e:
        print(f"❌ Error processing request: {e}")
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": f"Internal server error: {str(e)}"}
        )

# Instead of mounting FastMCP, let's create proper MCP endpoints
@app.post("/mcp")
async def handle_mcp_request(request: Request):
    """Handle MCP requests directly"""
    try:
        # The middleware has already verified authentication and set current_user_context
        body = await request.json()
        
        # Handle MCP protocol messages
        jsonrpc_version = body.get("jsonrpc", "2.0")
        method = body.get("method")
        params = body.get("params", {})
        request_id = body.get("id")
        
        print(f"🔧 MCP Request: {method}")
        
        if method == "initialize":
            return {
                "jsonrpc": jsonrpc_version,
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "OAuth MCP Server",
                        "version": "1.0.0"
                    }
                }
            }
        
        elif method == "tools/list":
            return {
                "jsonrpc": jsonrpc_version,
                "id": request_id,
                "result": {
                    "tools": [
                        {
                            "name": "echo",
                            "description": "Echo back the provided text",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "text": {"type": "string", "description": "Text to echo back"}
                                },
                                "required": ["text"]
                            }
                        },
                        {
                            "name": "get_time",
                            "description": "Get current server time",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        },
                        {
                            "name": "get_user_info",
                            "description": "Get current user information",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        }
                    ]
                }
            }
        
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            # Get user context from middleware
            username = current_user_context.get("username", "unknown")
            client_id = current_user_context.get("client_id", "unknown")
            
            if tool_name == "echo":
                text = arguments.get("text", "")
                result_text = f"Echo from {username}: {text}"
            elif tool_name == "get_time":
                result_text = f"Server time for {username}: {datetime.now().isoformat()}"
            elif tool_name == "get_user_info":
                result_text = f"Current user: {username}, Client ID: {client_id}"
            else:
                return {
                    "jsonrpc": jsonrpc_version,
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": f"Unknown tool: {tool_name}"
                    }
                }
            
            return {
                "jsonrpc": jsonrpc_version,
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": result_text
                        }
                    ]
                }
            }
        
        elif method == "notifications/initialized":
            # This is a notification, no response needed
            print("✅ MCP client initialized")
            return None
        
        else:
            return {
                "jsonrpc": jsonrpc_version,
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Unknown method: {method}"
                }
            }
    
    except Exception as e:
        print(f"❌ Error handling MCP request: {e}")
        return {
            "jsonrpc": "2.0",
            "id": request_id if 'request_id' in locals() else None,
            "error": {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        }

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    print("Starting OAuth MCP Server on http://localhost:9000")
    print("OAuth metadata available at: http://localhost:9000/.well-known/oauth-authorization-server")
    print("MCP endpoint available at: http://localhost:9000/mcp")
    uvicorn.run(app, host="0.0.0.0", port=9000)