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
from modules.whois_lookup_rdap import lookup_whois

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

        # Basic domain format validation (max 253 chars)
        if len(v) > 253:
            raise ValueError('Domain name too long (max 253 characters)')

        domain_pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if not re.match(domain_pattern, v):
            raise ValueError('Invalid domain format')

        return v

class IPRequest(BaseModel):
    ip: str

    @validator('ip')
    def validate_ip(cls, v):
        # Validate IPv4 format
        v = v.strip()
        ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(ipv4_pattern, v)

        if not match:
            raise ValueError('Invalid IPv4 address format')

        # Validate each octet is 0-255
        for octet in match.groups():
            if int(octet) > 255:
                raise ValueError('Invalid IPv4 address (octets must be 0-255)')

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
            "whois": "POST /api/whois - WHOIS data via RDAP protocol",
            "rdap": "POST /api/rdap - RDAP lookup (alias for /api/whois)",
            "reverse-ip": "POST /api/reverse-ip - Reverse IP lookup to find domains on same IP",
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
    WHOIS lookup endpoint using official RDAP protocol
    Returns domain registration data for confidence scoring
    """
    # Rate limiting check
    client_ip = req.client.host
    check_rate_limit(client_ip)

    domain = request.domain

    # Use RDAP-based WHOIS lookup
    result = await lookup_whois(domain)

    # Return result (already in correct format from RDAP module)
    return result

@app.post("/api/rdap")
async def rdap_proxy(request: DomainRequest, req: Request):
    """
    RDAP lookup endpoint (alias for /api/whois)
    Queries official TLD registries via RDAP protocol
    """
    # Rate limiting check
    client_ip = req.client.host
    check_rate_limit(client_ip)

    domain = request.domain

    # Use RDAP-based WHOIS lookup
    result = await lookup_whois(domain)

    # Return result (already in correct format from RDAP module)
    return result

@app.post("/api/reverse-ip")
async def reverse_ip_lookup(request: IPRequest, req: Request):
    """
    Reverse IP lookup endpoint via HackerTarget API
    Finds domains hosted on the same IP address
    """
    # Rate limiting check
    client_ip = req.client.host
    check_rate_limit(client_ip)

    ip = request.ip

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                follow_redirects=True
            )

            if response.status_code == 429:
                return {
                    "success": False,
                    "data": {
                        "domains": []
                    },
                    "error": f"Reverse IP lookup failed for {ip} (429 Too Many Requests)"
                }

            if response.status_code != 200:
                return {
                    "success": False,
                    "data": {
                        "domains": []
                    },
                    "error": f"Reverse IP lookup failed for {ip} ({response.status_code})"
                }

            text = response.text.strip()

            # Check for error responses
            if "error" in text.lower() or "invalid" in text.lower():
                return {
                    "success": False,
                    "data": {
                        "domains": []
                    },
                    "error": f"Reverse IP lookup returned error for {ip}"
                }

            # Parse text response (one domain per line)
            lines = text.split('\n')
            domains = []

            for line in lines:
                line = line.strip()
                # Filter out empty lines, error messages, and invalid domains
                if line and not line.startswith("error") and '.' in line:
                    domains.append(line)

            # Remove duplicates
            unique_domains = list(set(domains))

            return {
                "success": True,
                "data": {
                    "domains": unique_domains
                },
                "error": None
            }

    except httpx.TimeoutException:
        return {
            "success": False,
            "data": {
                "domains": []
            },
            "error": f"Reverse IP lookup timeout for {ip}"
        }
    except Exception as e:
        return {
            "success": False,
            "data": {
                "domains": []
            },
            "error": f"Reverse IP lookup error for {ip}: {str(e)}"
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
        async with httpx.AsyncClient(timeout=30.0) as client:  # Increased to 30 seconds for crt.sh
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

            # Validate if a string is a valid domain format
            def is_valid_domain(domain_str: str) -> bool:
                if not domain_str or not isinstance(domain_str, str):
                    return False

                # Reject domains with invalid characters (commas, spaces, quotes, parentheses, etc.)
                if re.search(r'[,\s\'"(){}\[\]<>|\\]', domain_str):
                    return False

                # Must contain at least one dot
                if '.' not in domain_str:
                    return False

                # Must match basic domain format (alphanumeric, dots, hyphens only)
                if not re.match(r'^[a-z0-9.-]+$', domain_str, re.IGNORECASE):
                    return False

                # Can't start or end with dot or hyphen
                if re.match(r'^[.-]|[.-]$', domain_str):
                    return False

                # Reject consecutive hyphens (e.g., "www--reddit.com")
                if '--' in domain_str:
                    return False

                # Reject consecutive dots (e.g., "example..com")
                if '..' in domain_str:
                    return False

                return True

            # Infrastructure provider blacklist - these are hosting/CDN services, not related domains
            infrastructure_providers = {
                # Cloudflare
                'cloudflare.com', 'cloudflaressl.com', 'cloudflare.net', 'cloudflare-dns.com',
                # Akamai
                'akamai.com', 'akamai.net', 'akamaiedge.net', 'akamaihd.net',
                # Fastly
                'fastly.com', 'fastly.net', 'fastlylb.net',
                # AWS
                'amazonaws.com', 'awsdns.com', 'awsdns.net', 'awsdns.org',
                # Other CDN/Cloud
                'cdn77.com', 'cdn77.net',
                'cloudfront.net',
                'googleusercontent.com', 'googleapis.com', 'gstatic.com',
                'azurewebsites.net', 'azure.com', 'windows.net',
                'digitaloceanspaces.com', 'digitalocean.com',
                # SSL/Security
                'letsencrypt.org', 'digicert.com', 'sectigo.com', 'godaddy.com', 'comodo.com',
                # Analytics
                'google-analytics.com', 'googletagmanager.com', 'doubleclick.net', 'googlesyndication.com'
            }

            # Helper function to extract apex/root domain
            def extract_apex_domain(domain_str: str) -> str:
                if not domain_str:
                    return ""

                # First validate the domain format
                if not is_valid_domain(domain_str):
                    return ""

                # Remove wildcards and clean up
                cleaned = domain_str.replace("*.", "").lower().strip()
                parts = cleaned.split(".")

                if len(parts) < 2:
                    return ""

                # Comprehensive list of multi-part TLDs (ccSLDs and special TLDs)
                multi_part_tlds = [
                    # UK
                    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'net.uk', 'me.uk',
                    # Australia
                    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
                    # New Zealand
                    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
                    # South Africa
                    'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za',
                    # Brazil
                    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
                    # Japan
                    'co.jp', 'or.jp', 'ne.jp', 'go.jp', 'ac.jp',
                    # Korea
                    'co.kr', 'or.kr', 'ne.kr', 'go.kr', 'ac.kr',
                    # India
                    'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in',
                    # Asia/Pacific
                    'com.sg', 'com.hk', 'com.tw', 'com.my', 'com.ph', 'com.vn', 'com.kh',
                    # Americas
                    'com.mx', 'com.ar', 'com.co', 'com.ve', 'com.pe', 'com.pr', 'com.bz', 'com.sv',
                    # Europe
                    'com.pl', 'com.tr', 'com.ua', 'com.ru',
                    # Middle East/Africa
                    'com.sa', 'com.eg', 'com.ng', 'com.gh', 'com.ke', 'com.ge',
                    # Other
                    'com.pk', 'com.bd', 'com.np'
                ]

                # Check if domain ends with multi-part TLD
                if len(parts) >= 3:
                    last_two_parts = '.'.join(parts[-2:])
                    if last_two_parts in multi_part_tlds:
                        apex = '.'.join(parts[-3:])

                        # Validate: ensure the third-level part is not empty and not just a number
                        third_level = parts[-3]
                        if not third_level or len(third_level) < 2 or third_level.isdigit():
                            return ""  # Invalid

                        # Filter out infrastructure providers
                        if apex in infrastructure_providers:
                            return ""  # Blacklisted

                        return apex

                # Standard TLD - return last 2 parts (domain.tld)
                apex = '.'.join(parts[-2:])

                # Validate: ensure the second-level part is not empty and not just a number
                second_level = parts[-2]
                if not second_level or len(second_level) < 2 or second_level.isdigit():
                    return ""  # Invalid

                # Filter out infrastructure providers
                if apex in infrastructure_providers:
                    return ""  # Blacklisted

                return apex

            # Extract unique APEX domains only (no subdomains)
            apex_domains = set()
            original_apex = extract_apex_domain(domain)

            # Process certificates to find related apex domains
            for cert in certificates:
                # Extract from common_name
                if cert.get("common_name"):
                    clean_domain = (
                        cert["common_name"]
                        .replace("*.", "")
                        .lower()
                        .strip()
                    )

                    apex = extract_apex_domain(clean_domain)

                    # Only include apex domains that are different from the original
                    if apex and apex != original_apex and len(apex) >= 3:
                        apex_domains.add(apex)

                # Extract from Subject Alternative Names (SANs)
                if cert.get("name_value"):
                    sans = cert["name_value"].split('\n')
                    for san in sans:
                        clean_domain = (
                            san.replace("*.", "")
                            .lower()
                            .strip()
                        )

                        apex = extract_apex_domain(clean_domain)

                        # Only include apex domains that are different from the original
                        if apex and apex != original_apex and len(apex) >= 3:
                            apex_domains.add(apex)

            # Limit to top 10 unique apex domains
            related_domains_array = list(apex_domains)[:10]

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
