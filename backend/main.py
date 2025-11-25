from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
import asyncio
import re
from typing import Dict, Any

from modules.dns_lookup import perform_dns_lookup

app = FastAPI(
    title="Strivyr Survey API",
    description="Open-source domain intelligence gathering API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS for external frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this with your frontend domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
async def lookup_domain(request: DomainRequest):
    """
    Perform comprehensive domain reconnaissance
    """
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
