#!/usr/bin/env python3
"""
Simple OAuth Client for the OAuth MCP Server
This client demonstrates how to authenticate and call MCP tools.
"""

import json
import secrets
import hashlib
import base64
import webbrowser
import time
from urllib.parse import urlencode, parse_qs, urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import requests

class CallbackHandler(BaseHTTPRequestHandler):
    """Handler for OAuth callback"""
    
    def do_GET(self):
        # Parse the callback URL
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        if 'code' in params:
            # Store the authorization code
            self.server.auth_code = params['code'][0]
            self.server.state = params.get('state', [None])[0]
            
            # Send success response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'''
                <html><body>
                <h1>Authorization Successful!</h1>
                <p>You can close this window and return to the terminal.</p>
                <script>window.close();</script>
                </body></html>
            ''')
        else:
            # Handle error
            self.send_response(400)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>Authorization Failed</h1></body></html>')
    
    def log_message(self, format, *args):
        # Suppress logging
        pass

class SimpleOAuthClient:
    """Simple OAuth 2.1 client with PKCE support"""
    
    def __init__(self, server_base_url="http://localhost:9000"):
        self.server_base_url = server_base_url
        self.client_id = None
        self.client_secret = None
        self.access_token = None
        self.redirect_uri = "http://localhost:8080/callback"
        
    def generate_pkce_params(self):
        """Generate PKCE code verifier and challenge"""
        # Generate code verifier (43-128 chars)
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Generate code challenge (SHA256 hash of verifier)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    def register_client(self):
        """Register this client with the OAuth server"""
        print("🔧 Registering OAuth client...")
        
        registration_data = {
            "client_name": "Simple MCP Client",
            "redirect_uris": [self.redirect_uri],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "read write"
        }
        
        try:
            response = requests.post(
                f"{self.server_base_url}/oauth/register",
                json=registration_data,
                timeout=10
            )
            response.raise_for_status()
            
            client_info = response.json()
            self.client_id = client_info["client_id"]
            self.client_secret = client_info["client_secret"]
            
            print(f"✅ Client registered successfully!")
            print(f"   Client ID: {self.client_id[:20]}...")
            return True
            
        except Exception as e:
            print(f"❌ Client registration failed: {e}")
            return False
    
    def start_auth_flow(self):
        """Start the OAuth authorization flow"""
        if not self.client_id:
            print("❌ Client not registered. Call register_client() first.")
            return False
        
        print("🔐 Starting OAuth authorization flow...")
        
        # Generate PKCE parameters
        code_verifier, code_challenge = self.generate_pkce_params()
        state = secrets.token_urlsafe(16)
        
        # Start callback server
        callback_server = HTTPServer(('localhost', 8080), CallbackHandler)
        callback_server.auth_code = None
        callback_server.state = None
        
        # Start server in background thread
        server_thread = threading.Thread(target=callback_server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        print("🌐 Starting callback server on http://localhost:8080")
        
        # Build authorization URL
        auth_params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "scope": "read write"
        }
        
        auth_url = f"{self.server_base_url}/oauth/authorize?{urlencode(auth_params)}"
        
        print(f"🚀 Opening browser for authorization...")
        print(f"   URL: {auth_url}")
        webbrowser.open(auth_url)
        
        # Wait for callback
        print("⏳ Waiting for authorization callback...")
        timeout = 60  # 60 seconds timeout
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if callback_server.auth_code:
                print("✅ Authorization code received!")
                break
            time.sleep(0.5)
        else:
            print("❌ Timeout waiting for authorization")
            callback_server.shutdown()
            return False
        
        # Exchange code for token
        success = self.exchange_code_for_token(
            callback_server.auth_code, 
            code_verifier
        )
        
        callback_server.shutdown()
        return success
    
    def exchange_code_for_token(self, auth_code, code_verifier):
        """Exchange authorization code for access token"""
        print("🔄 Exchanging authorization code for access token...")
        
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code_verifier": code_verifier
        }
        
        try:
            response = requests.post(
                f"{self.server_base_url}/oauth/token",
                data=token_data,
                timeout=10
            )
            response.raise_for_status()
            
            token_info = response.json()
            self.access_token = token_info["access_token"]
            
            print("✅ Access token received!")
            print(f"   Token: {self.access_token[:30]}...")
            print(f"   Expires in: {token_info.get('expires_in', 'unknown')} seconds")
            return True
            
        except Exception as e:
            print(f"❌ Token exchange failed: {e}")
            return False
    
    def call_mcp_method(self, method, params=None):
        """Call an MCP method with authentication"""
        if not self.access_token:
            print("❌ No access token. Complete authentication first.")
            return None
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "id": 1
        }
        
        if params:
            payload["params"] = params
        
        try:
            response = requests.post(
                f"{self.server_base_url}/mcp",
                json=payload,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            print(f"❌ MCP call failed: {e}")
            return None
    
    def initialize_mcp(self):
        """Initialize MCP connection"""
        print("🔧 Initializing MCP connection...")
        result = self.call_mcp_method("initialize")
        if result and "result" in result:
            print("✅ MCP initialized successfully!")
            return True
        else:
            print("❌ MCP initialization failed")
            return False
    
    def list_tools(self):
        """List available MCP tools"""
        print("📋 Listing available tools...")
        result = self.call_mcp_method("tools/list")
        
        if result and "result" in result and "tools" in result["result"]:
            tools = result["result"]["tools"]
            print(f"✅ Found {len(tools)} tools:")
            for i, tool in enumerate(tools, 1):
                print(f"   {i}. {tool['name']}: {tool.get('description', 'No description')}")
            return tools
        else:
            print("❌ Failed to list tools")
            return []
    
    def call_tool(self, tool_name, arguments=None):
        """Call a specific MCP tool"""
        print(f"🛠️  Calling tool: {tool_name}")
        
        params = {
            "name": tool_name,
            "arguments": arguments or {}
        }
        
        result = self.call_mcp_method("tools/call", params)
        
        if result and "result" in result:
            content = result["result"].get("content", [])
            print("✅ Tool response:")
            for item in content:
                if item.get("type") == "text":
                    print(f"   {item['text']}")
            return result
        else:
            print("❌ Tool call failed")
            return None

def main():
    """Main function demonstrating the OAuth client"""
    print("🚀 Simple OAuth MCP Client")
    print("=" * 40)
    
    # Create client
    client = SimpleOAuthClient()
    
    # Step 1: Register client
    if not client.register_client():
        return
    
    print()
    
    # Step 2: Authenticate
    if not client.start_auth_flow():
        return
    
    print()
    
    # Step 3: Initialize MCP
    if not client.initialize_mcp():
        return
    
    print()
    
    # Step 4: List tools
    tools = client.list_tools()
    
    print()
    
    # Step 5: Call some tools
    if tools:
        # Call echo tool
        print("🧪 Testing echo tool...")
        client.call_tool("echo", {"text": "Hello from OAuth client!"})
        
        print()
        
        # Call get_time tool
        print("🧪 Testing get_time tool...")
        client.call_tool("get_time")
        
        print()
        
        # Call get_user_info tool
        print("🧪 Testing get_user_info tool...")
        client.call_tool("get_user_info")
    
    print()
    print("✅ OAuth MCP Client demo completed!")

if __name__ == "__main__":
    main()