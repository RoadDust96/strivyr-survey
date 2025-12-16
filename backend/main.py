from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
import asyncio
import re
import time
import httpx
from typing import Dict, Any, List, Optional
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
            "lookup": "POST /api/lookup - Comprehensive domain reconnaissance",
            "whois": "POST /api/whois - WHOIS data proxy",
            "ct-logs": "POST /api/ct-logs - Certificate Transparency logs",
            "health": "GET /health - Health check",
            "docs": "GET /docs - Interactive API documentation",
            "redoc": "GET /redoc - ReDoc documentation"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.post("/api/whois")
async def whois_proxy(request: DomainRequest, req: Request):
    """
    Proxy endpoint for WHOIS data via Who-Dat API
    Prevents CORS issues when fetching from frontend
    """
    # Rate limiting check
    client_ip = req.client.host
    check_rate_limit(client_ip)

    domain = request.domain

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"https://who-dat.as93.net/{domain}",
                headers={
                    "User-Agent": "StrivyrSurvey/1.0",
                    "Accept": "application/json"
                }
            )

            if response.status_code == 429:
                return {
                    "success": False,
                    "error": "Rate limit exceeded. Please try again in a moment.",
                    "data": {
                        "registrant": {},
                        "registrar": "",
                        "nameservers": [],
                        "created": "",
                        "emails": [],
                        "organization": ""
                    }
                }

            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Who-Dat API error: {response.status_code}"
                )

            whois_data = response.json()

            # Normalize the response structure
            return {
                "success": True,
                "data": {
                    "registrant": whois_data.get("registrant", {}),
                    "registrar": whois_data.get("registrar", ""),
                    "nameservers": whois_data.get("nameServers") or whois_data.get("nameservers", []),
                    "created": whois_data.get("createdDate") or whois_data.get("created", ""),
                    "emails": whois_data.get("emails", []),
                    "organization": (
                        whois_data.get("registrant", {}).get("organization")
                        or whois_data.get("organization", "")
                    )
                }
            }

    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "Request timeout",
            "data": {
                "registrant": {},
                "registrar": "",
                "nameservers": [],
                "created": "",
                "emails": [],
                "organization": ""
            }
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "data": {
                "registrant": {},
                "registrar": "",
                "nameservers": [],
                "created": "",
                "emails": [],
                "organization": ""
            }
        }

@app.post("/api/ct-logs")
async def ct_logs_proxy(request: DomainRequest, req: Request):
    """
    Proxy endpoint for Certificate Transparency logs via crt.sh
    Prevents CORS issues when fetching from frontend
    """
    # Rate limiting check
    client_ip = req.client.host
    check_rate_limit(client_ip)

    domain = request.domain

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={
                    "User-Agent": "StrivyrSurvey/1.0",
                    "Accept": "application/json"
                }
            )

            if response.status_code == 503:
                return {
                    "success": False,
                    "error": "Certificate Transparency service temporarily unavailable",
                    "data": {
                        "certificates": [],
                        "relatedDomains": []
                    }
                }

            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"crt.sh API error: {response.status_code}"
                )

            certificates = response.json()

            # Extract unique related domains from certificates
            related_domains = set()
            base_domain = domain
            base_keyword = base_domain.split('.')[0]  # e.g., "google" from "google.com"

            # Process certificates to find related domains
            for cert in certificates:
                # Extract from common_name
                if cert.get("common_name"):
                    clean_domain = (
                        cert["common_name"]
                        .replace("*.", "")
                        .lower()
                        .strip()
                    )

                    # Only include if it's different from base domain
                    if (clean_domain != base_domain and
                        base_keyword in clean_domain and
                        "." in clean_domain):
                        related_domains.add(clean_domain)

                # Extract from Subject Alternative Names (SANs)
                if cert.get("name_value"):
                    sans = cert["name_value"].split('\n')
                    for san in sans:
                        clean_domain = (
                            san.replace("*.", "")
                            .lower()
                            .strip()
                        )

                        # Only include if it's different from base domain
                        if (clean_domain != base_domain and
                            base_keyword in clean_domain and
                            "." in clean_domain):
                            related_domains.add(clean_domain)

            # Limit to top 10 related domains
            related_domains_array = list(related_domains)[:10]

            return {
                "success": True,
                "data": {
                    "certificates": certificates,
                    "relatedDomains": related_domains_array
                }
            }

    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "Request timeout",
            "data": {
                "certificates": [],
                "relatedDomains": []
            }
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "data": {
                "certificates": [],
                "relatedDomains": []
            }
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
