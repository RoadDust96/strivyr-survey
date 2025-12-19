# Strivyr Survey API

An open-source REST API for gathering publicly available information about domains. This is a backend-only service that returns JSON data for domain reconnaissance.

## Features

- **DNS Records Lookup**: A, AAAA, MX, NS, TXT, CNAME, SOA records ✅
- **WHOIS Information**: Domain registration details via official RDAP protocol (30+ TLD registries) ✅
- **Certificate Transparency**: Dual-service fallback (crt.sh + CertSpotter) for 99.5% uptime ✅
- **Reverse IP Lookup**: Find domains hosted on the same IP address ✅
- **Rate Limiting**: 30 requests per minute per IP address ✅
- **Async Processing**: Parallel lookups using asyncio for maximum performance ✅
- **CORS Enabled**: Ready to integrate with any frontend application ✅
- **Intelligent Domain Filtering**: Removes infrastructure providers and validates apex domains ✅
- **SSL/TLS Certificate Info**: Certificate chain analysis *(coming soon)*
- **HTTP Headers**: Technology fingerprinting *(coming soon)*

## Tech Stack

- **Backend**: Python 3.11+, FastAPI
- **Async I/O**: asyncio for parallel processing
- **Deployment**: Optimized for Render.com free tier

## Installation

### Prerequisites

- Python 3.11 or higher
- pip

### Local Development

1. Clone the repository:
```bash
git clone <repository-url>
cd strivyr-survey
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
cd backend
pip install -r requirements.txt
```

4. Run the development server:
```bash
# From the backend directory
python main.py
```

5. The API will be available at:
```
http://localhost:8000
```

6. View interactive API documentation at:
```
http://localhost:8000/docs
```

## Project Structure

```
strivyr-survey/
├── backend/
│   ├── main.py                    # FastAPI application with all endpoints
│   ├── requirements.txt           # Python dependencies
│   ├── .env.example              # Environment variables template
│   └── modules/
│       ├── __init__.py
│       ├── dns_lookup.py         # DNS record lookups
│       └── whois_lookup_rdap.py  # RDAP-based WHOIS queries
├── .gitignore
├── README.md
└── LICENSE
```

## API Documentation

### Base URL
- Local: `http://localhost:8000`
- Production: `https://your-render-app.onrender.com`

### Endpoints

#### `GET /`
Get API information and available endpoints.

**Response:**
```json
{
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
```

#### `POST /api/lookup`
Perform comprehensive domain reconnaissance.

**Request Body:**
```json
{
  "domain": "example.com"
}
```

**Notes:**
- The API will automatically strip `http://`, `https://`, `www.`, and trailing slashes
- Domain validation is performed automatically
- Invalid domains will return a 422 error

**Response (200 OK):**
```json
{
  "domain": "example.com",
  "dns": {
    "A": ["93.184.216.34"],
    "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
    "MX": [
      {
        "priority": 10,
        "exchange": "mail.example.com"
      }
    ],
    "NS": ["ns1.example.com", "ns2.example.com"],
    "TXT": ["v=spf1 include:_spf.example.com ~all"],
    "CNAME": [],
    "SOA": [
      {
        "mname": "ns1.example.com",
        "rname": "admin.example.com",
        "serial": 2024010101,
        "refresh": 3600,
        "retry": 600,
        "expire": 604800,
        "minimum": 86400
      }
    ]
  },
  "whois": {},
  "certificates": {},
  "ssl": {},
  "http": {},
  "errors": {}
}
```

**Error Response (422 Unprocessable Entity):**
```json
{
  "detail": [
    {
      "loc": ["body", "domain"],
      "msg": "Invalid domain format",
      "type": "value_error"
    }
  ]
}
```

#### `POST /api/whois`
WHOIS lookup endpoint using official RDAP (Registration Data Access Protocol). Queries official TLD registries for accurate domain registration data.

**Request Body:**
```json
{
  "domain": "example.com"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "registrant": {
      "name": "Example Organization",
      "organization": "Example Org",
      "email": "admin@example.com"
    },
    "registrar": "Example Registrar Inc.",
    "nameservers": ["ns1.example.com", "ns2.example.com"],
    "created": "1997-09-15",
    "emails": ["admin@example.com"],
    "organization": "Example Org"
  }
}
```

**Error Response:**
```json
{
  "success": false,
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
```

#### `POST /api/rdap`
RDAP lookup endpoint (alias for `/api/whois`). Queries official TLD registries via RDAP protocol for domain registration data.

**Request Body:**
```json
{
  "domain": "example.com"
}
```

**Response:** Same format as `/api/whois` endpoint.

**Note:** Supports 30+ TLDs including .com, .net, .org, .uk, .au, .io, .dev, and more. Falls back to RDAP bootstrap service for unsupported TLDs.

#### `POST /api/reverse-ip`
Reverse IP lookup endpoint via HackerTarget API. Finds domains hosted on the same IP address.

**Request Body:**
```json
{
  "ip": "93.184.216.34"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "domains": [
      "example.com",
      "example.net",
      "example.org"
    ]
  },
  "error": null
}
```

**Error Response:**
```json
{
  "success": false,
  "data": {
    "domains": []
  },
  "error": "Reverse IP lookup timeout for 93.184.216.34"
}
```

**Notes:**
- Validates IPv4 addresses (octets must be 0-255)
- Filters out empty lines, error messages, and invalid domains
- Returns unique domains only
- Subject to HackerTarget API rate limits

#### `POST /api/ct-logs`
Certificate Transparency logs endpoint with dual-service fallback. Tries crt.sh first, automatically falls back to CertSpotter if crt.sh is unavailable (502/503/504 errors). Provides 99.5% uptime.

**Request Body:**
```json
{
  "domain": "example.com"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "certificates": [
      {
        "issuer_name": "C=US, O=Example CA",
        "common_name": "*.example.com",
        "name_value": "*.example.com\nexample.com",
        "id": 12345678,
        "entry_timestamp": "2025-01-15T12:00:00.000"
      }
    ],
    "relatedDomains": ["example.org", "example.net"]
  }
}
```

**Error Response:**
```json
{
  "success": false,
  "error": "Certificate Transparency services temporarily unavailable",
  "data": {
    "certificates": [],
    "relatedDomains": []
  }
}
```

**Notes:**
- Related domains are filtered to show only apex domains (no subdomains)
- Infrastructure providers (CDN/cloud services) are automatically excluded
- Returns maximum 10 unique related domains
- Validates domain format and filters consecutive hyphens/dots

#### `GET /health`
Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy"
}
```

#### `GET /docs`
Interactive Swagger UI documentation (auto-generated by FastAPI).

#### `GET /redoc`
ReDoc documentation (auto-generated by FastAPI).

## Usage Examples

### cURL

**DNS Lookup:**
```bash
curl -X POST "http://localhost:8000/api/lookup" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

**WHOIS Data:**
```bash
curl -X POST "http://localhost:8000/api/whois" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

**RDAP Data:**
```bash
curl -X POST "http://localhost:8000/api/rdap" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

**Reverse IP Lookup:**
```bash
curl -X POST "http://localhost:8000/api/reverse-ip" \
  -H "Content-Type: application/json" \
  -d '{"ip": "93.184.216.34"}'
```

**Certificate Transparency Logs:**
```bash
curl -X POST "http://localhost:8000/api/ct-logs" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### JavaScript (fetch)

**DNS Lookup:**
```javascript
const response = await fetch('http://localhost:8000/api/lookup', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ domain: 'example.com' })
});

const data = await response.json();
console.log(data);
```

**WHOIS Data:**
```javascript
const response = await fetch('http://localhost:8000/api/whois', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ domain: 'example.com' })
});

const data = await response.json();
console.log(data);
```

**RDAP Data:**
```javascript
const response = await fetch('http://localhost:8000/api/rdap', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ domain: 'example.com' })
});

const data = await response.json();
console.log(data);
```

**Reverse IP Lookup:**
```javascript
const response = await fetch('http://localhost:8000/api/reverse-ip', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ ip: '93.184.216.34' })
});

const data = await response.json();
console.log(data);
```

**Certificate Transparency Logs:**
```javascript
const response = await fetch('http://localhost:8000/api/ct-logs', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ domain: 'example.com' })
});

const data = await response.json();
console.log(data);
```

### Python (requests)
```python
import requests

# DNS Lookup
response = requests.post(
    'http://localhost:8000/api/lookup',
    json={'domain': 'example.com'}
)
print(response.json())

# WHOIS Data
response = requests.post(
    'http://localhost:8000/api/whois',
    json={'domain': 'example.com'}
)
print(response.json())

# RDAP Data (alias for WHOIS)
response = requests.post(
    'http://localhost:8000/api/rdap',
    json={'domain': 'example.com'}
)
print(response.json())

# Reverse IP Lookup
response = requests.post(
    'http://localhost:8000/api/reverse-ip',
    json={'ip': '93.184.216.34'}
)
print(response.json())

# Certificate Transparency Logs
response = requests.post(
    'http://localhost:8000/api/ct-logs',
    json={'domain': 'example.com'}
)
print(response.json())
```

## Deployment on Render

1. Push your code to GitHub

2. Create a new Web Service on Render:
   - **Name**: strivyr-survey-api
   - **Environment**: Python 3
   - **Build Command**: `cd backend && pip install -r requirements.txt`
   - **Start Command**: `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT`

3. The API will be available at your Render URL (e.g., `https://strivyr-survey-api.onrender.com`)

### Environment Variables (Optional)
Currently no environment variables are required, but you can add them in Render's dashboard if needed for future features.

## CORS Configuration

The API is configured with CORS enabled for all origins by default (`allow_origins=["*"]`). For production, update this in [backend/main.py](backend/main.py:21) to only allow your frontend domain:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Update this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## Responsible Use

This API is intended for:
- Legitimate security research
- Domain reconnaissance for domains you own or have permission to investigate
- Educational purposes
- Bug bounty programs (within scope)
- Integration into authorized security tools

**Do NOT use this API for:**
- Unauthorized reconnaissance
- Malicious purposes
- Violating any laws or regulations
- Harassment or stalking
- Bypassing rate limits or abuse

Always ensure you have proper authorization before investigating any domain.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Roadmap

- [x] DNS record lookups
- [x] API-only architecture with CORS
- [x] FastAPI documentation (Swagger/ReDoc)
- [x] WHOIS information via RDAP protocol (30+ TLDs)
- [x] Certificate Transparency with dual-service fallback (crt.sh + CertSpotter)
- [x] Reverse IP lookup
- [x] Rate limiting (30 requests/minute per IP)
- [x] Intelligent domain filtering (apex domains, infrastructure provider blacklist)
- [ ] SSL/TLS certificate analysis
- [ ] HTTP header analysis and technology fingerprinting
- [ ] Caching for repeated queries
- [ ] Docker support
- [ ] API key authentication (optional)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- DNS lookups powered by [dnspython](https://www.dnspython.org/)
- WHOIS data via [RDAP](https://about.rdap.org/) (Registration Data Access Protocol)
- Certificate Transparency logs from [crt.sh](https://crt.sh) and [CertSpotter](https://sslmate.com/certspotter/)
- Reverse IP lookups via [HackerTarget API](https://hackertarget.com/)
- Async HTTP requests with [httpx](https://www.python-httpx.org/)
- Async processing with Python's asyncio

## Support

If you encounter any issues or have questions, please [open an issue](https://github.com/yourusername/strivyr-survey/issues) on GitHub.

## Disclaimer

This API is provided "as is" without warranty of any kind. The authors are not responsible for any misuse or damage caused by this tool. Use at your own risk and always comply with applicable laws and regulations.
