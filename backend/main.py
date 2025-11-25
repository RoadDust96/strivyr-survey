from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
import asyncio
import re
import time
from typing import Dict, Any
from collections import defaultdict

from modules.dns_lookup import perform_dns_lookup

app = FastAPI(
    title="Strivyr Survey API",
    description="Open-source domain intelligence gathering API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS for external frontend
# IMPORTANT: This must be added BEFORE other middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production: ["https://strivyr.com", "https://www.strivyr.com"]
    allow_credentials=False,  # Changed from True for security with wildcard origins
    allow_methods=["POST", "GET", "OPTIONS"],  # Only allow necessary methods
    allow_headers=["Content-Type"],
    expose_headers=["*"],  # Important: expose all headers to the frontend
)

# Rate limiting configuration
rate_limit_store = defaultdict(list)
MAX_REQUESTS = 30  # Max 30 requests per IP
TIME_WINDOW = 60  # Per 60 seconds (1 minute)

def check_rate_limit(client_ip: str):
    """Check if client has exceeded rate limit"""
    now = time.time()

    # Remove old requests outside the time window
    rate_limit_store[client_ip] = [
        timestamp for timestamp in rate_limit_store[client_ip]
        if now - timestamp < TIME_WINDOW
    ]

    # Check if limit exceeded
    if len(rate_limit_store[client_ip]) >= MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Maximum {MAX_REQUESTS} requests per minute."
        )

    # Add current request
    rate_limit_store[client_ip].append(now)

class DomainRequest(BaseModel):
    domain: str

    @validator('domain')
    def validate_domain(cls, v):
        # Basic domain validation
        v = v.strip().lower()
        # Remove http:// or https:// if present
        v = re.sub(r'^https?://', '', v)
        # Remove trailing slash
        v = v.rstrip('/')
        # Remove www. prefix for consistency
        v = re.sub(r'^www\.', '', v)

        # Basic domain format validation
        domain_pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if not re.match(domain_pattern, v):
            raise ValueError('Invalid domain format')

        return v

class DomainResponse(BaseModel):
    domain: str
    dns: Dict[str, Any]
    whois: Dict[str, Any] = {}
    certificates: Dict[str, Any] = {}
    ssl: Dict[str, Any] = {}
    http: Dict[str, Any] = {}
    errors: Dict[str, str] = {}

@app.post("/api/lookup", response_model=DomainResponse)
async def lookup_domain(request: DomainRequest, req: Request):
    """
    Perform comprehensive domain reconnaissance
    """
    # Rate limiting check
    client_ip = req.client.host
    check_rate_limit(client_ip)

    domain = request.domain

    # Initialize response structure
    response = {
        "domain": domain,
        "dns": {},
        "whois": {},
        "certificates": {},
        "ssl": {},
        "http": {},
        "errors": {}
    }

    # Perform all lookups in parallel
    tasks = [
        ("dns", perform_dns_lookup(domain)),
        # Add more modules here as they are implemented
        # ("whois", perform_whois_lookup(domain)),
        # ("certificates", perform_cert_transparency_search(domain)),
        # ("ssl", perform_ssl_lookup(domain)),
        # ("http", perform_http_fingerprint(domain)),
    ]

    # Execute all tasks concurrently
    results = await asyncio.gather(*[task[1] for task in tasks], return_exceptions=True)

    # Process results
    for (name, _), result in zip(tasks, results):
        if isinstance(result, Exception):
            response["errors"][name] = str(result)
        else:
            response[name] = result

    return response

@app.get("/")
async def root():
    """Root endpoint - API information"""
    return {
        "name": "Strivyr Survey API",
        "version": "1.0.0",
        "description": "Open-source domain intelligence gathering API",
        "endpoints": {
            "lookup": "POST /api/lookup",
            "health": "GET /health",
            "docs": "GET /docs",
            "redoc": "GET /redoc"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
