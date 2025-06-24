# OAuth MCP Server

A beginner-friendly implementation of an OAuth 2.1 server with Model Context Protocol (MCP) integration. This server provides secure authentication for MCP tools and services.

## 🌟 What is this?

This project combines two important technologies:

- **OAuth 2.1**: A modern, secure way for applications to get permission to access user data
- **MCP (Model Context Protocol)**: A protocol that allows AI models to securely interact with external tools and services

Think of it as a secure gateway that allows AI assistants to use tools on your behalf, but only after proper authentication.

## 🚀 Quick Start

### Prerequisites

Before you begin, make sure you have:

- Python 3.8 or higher installed
- Basic understanding of command line/terminal
- A text editor or IDE

### Installation

1. **Clone or download this project**
   ```bash
   # If using git
   git clone <repository-url>
   cd oauth-mcp-server
   
   # Or download the files directly and extract them
   ```

2. **Install required dependencies**
   ```bash
   pip install fastapi uvicorn python-jose[cryptography] python-multipart
   ```

3. **Run the server**
   ```bash
   python oauth_mcp_server.py
   ```

4. **Verify it's working**
   Open your browser and go to: http://localhost:9000/health
   
   You should see: `{"status": "healthy", "timestamp": "..."}`

## 🔧 How to Use

### Step 1: Register a Client Application

Before any application can use your OAuth server, it needs to register:

```bash
curl -X POST "http://localhost:9000/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Test App",
    "redirect_uris": ["http://localhost:8080/callback"],
    "scope": "read write"
  }'
```

**You'll get back something like:**
```json
{
  "client_id": "abc123...",
  "client_secret": "xyz789...",
  "redirect_uris": ["http://localhost:8080/callback"],
  ...
}
```

**💡 Save these credentials!** You'll need them for the next steps.

### Step 2: Get Authorization

Your application needs to redirect users to get permission:

```
http://localhost:9000/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:8080/callback&state=random123
```

**What happens:**
1. User visits this URL
2. Server automatically approves (for demo purposes)
3. User gets redirected back with an authorization code

### Step 3: Exchange Code for Token

Use the authorization code to get an access token:

```bash
curl -X POST "http://localhost:9000/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=YOUR_AUTH_CODE&redirect_uri=http://localhost:8080/callback&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET"
```

**You'll get back:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### Step 4: Use MCP Tools

Now you can use the access token to call MCP tools:

```bash
curl -X POST "http://localhost:9000/mcp" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "echo",
      "arguments": {"text": "Hello, World!"}
    }
  }'
```

## 🛠️ Available MCP Tools

The server comes with three demo tools:

### 1. Echo Tool
Repeats back whatever you send it.

**Example:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "echo",
    "arguments": {"text": "Hello!"}
  }
}
```

### 2. Get Time Tool
Returns the current server time.

**Example:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "get_time",
    "arguments": {}
  }
}
```

### 3. Get User Info Tool
Returns information about the authenticated user.

**Example:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "get_user_info",
    "arguments": {}
  }
}
```

## 🔒 Security Features

### PKCE Support (Proof Key for Code Exchange)

For extra security, especially with mobile apps or single-page applications:

1. **Generate a code verifier** (random string)
2. **Create a code challenge** (SHA256 hash of verifier, base64url encoded)
3. **Include in authorization request:**
   ```
   http://localhost:9000/oauth/authorize?...&code_challenge=CHALLENGE&code_challenge_method=S256
   ```
4. **Include verifier in token request:**
   ```bash
   curl -X POST "http://localhost:9000/oauth/token" \
     -d "...&code_verifier=YOUR_VERIFIER"
   ```

### Demo User Account

The server includes a demo user:
- **Username:** demo
- **Password:** demo123

*Note: In production, you'd implement proper user authentication!*

## 🌐 Important Endpoints

| Endpoint | Purpose | Method |
|----------|---------|---------|
| `/.well-known/oauth-authorization-server` | OAuth server metadata | GET |
| `/oauth/register` | Register new client | POST |
| `/oauth/authorize` | Get authorization code | GET |
| `/oauth/token` | Exchange code for token | POST |
| `/mcp` | MCP protocol endpoint | POST |
| `/health` | Health check | GET |

## 🚨 Production Considerations

**⚠️ This is a demo implementation!** Before using in production:

1. **Change the secret key** - Use a strong, random secret
2. **Add proper user authentication** - The demo auto-approves everything
3. **Use HTTPS** - Never run OAuth over HTTP in production
4. **Add rate limiting** - Prevent abuse
5. **Add proper logging** - For security monitoring
6. **Validate all inputs** - Add comprehensive input validation
7. **Use a real database** - Currently uses in-memory storage

## 🔧 Configuration

You can modify these settings in the code:

```python
SECRET_KEY = "your-secret-key"  # Change this!
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Token lifetime
```

## 🐛 Troubleshooting

### Common Issues

**Problem:** "Invalid client_id"
- **Solution:** Make sure you're using the exact client_id from registration

**Problem:** "Invalid redirect_uri"
- **Solution:** The redirect_uri must exactly match what you registered

**Problem:** "Missing authorization header"
- **Solution:** Include `Authorization: Bearer YOUR_TOKEN` in MCP requests

**Problem:** Server won't start
- **Solution:** Check if port 9000 is available, or change the port in the code

### Enable Debug Logging

The server prints helpful debug information. Watch the console output to see:
- Client registrations
- Authorization requests
- Token exchanges
- MCP requests

## 📚 Learn More

- [OAuth 2.1 Specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [PKCE RFC](https://datatracker.ietf.org/doc/html/rfc7636)
- [Model Context Protocol](https://github.com/modelcontextprotocol)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

## 🤝 Contributing

This is a learning project! Feel free to:
- Add more MCP tools
- Improve security features
- Add better error handling
- Create example client applications

## 📄 License

This project is for educational purposes. Use responsibly and add proper security measures for production use.
