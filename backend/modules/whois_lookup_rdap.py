"""
RDAP-based WHOIS lookup module for Strivyr Survey
Replaces unreliable third-party WHOIS services with official RDAP protocol
"""

import httpx
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

# Official RDAP servers by TLD
RDAP_SERVERS = {
    # Generic TLDs
    'com': 'https://rdap.verisign.com/com/v1/domain/',
    'net': 'https://rdap.verisign.com/net/v1/domain/',
    'org': 'https://rdap.publicinterestregistry.org/rdap/domain/',
    'info': 'https://rdap.afilias.info/rdap/domain/',
    'biz': 'https://rdap.afilias.info/rdap/domain/',
    'us': 'https://rdap.nic.us/domain/',

    # Country code TLDs
    'uk': 'https://rdap.nominet.uk/uk/domain/',
    'au': 'https://rdap.ausregistry.net.au/rdap/domain/',
    'ca': 'https://rdap.ca.fury.ca/rdap/domain/',
    'de': 'https://rdap.denic.de/domain/',
    'fr': 'https://rdap.nic.fr/domain/',
    'jp': 'https://rdap.nic.ad.jp/domain/',
    'cn': 'https://rdap.cnnic.cn/domain/',
    'br': 'https://rdap.registro.br/domain/',
    'in': 'https://rdap.registry.in/domain/',
    'mx': 'https://rdap.mx/domain/',

    # New gTLDs
    'io': 'https://rdap.nic.io/domain/',
    'ai': 'https://rdap.nic.ai/domain/',
    'co': 'https://rdap.nic.co/domain/',
    'dev': 'https://rdap.nic.google/domain/',
    'app': 'https://rdap.nic.google/domain/',
    'tech': 'https://rdap.nic.tech/domain/',
    'online': 'https://rdap.nic.online/domain/',
    'xyz': 'https://rdap.nic.xyz/domain/',
    'me': 'https://rdap.nic.me/domain/',
    'tv': 'https://rdap.nic.tv/domain/',
    'cc': 'https://rdap.nic.cc/domain/',
}


def extract_tld(domain: str) -> str:
    """Extract top-level domain from domain name"""
    parts = domain.lower().split('.')

    # Handle multi-part TLDs (e.g., co.uk)
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in ['co.uk', 'com.au', 'co.nz']:
        return f"{parts[-2]}.{parts[-1]}"

    return parts[-1]


def parse_vcard(vcard_array: Optional[List]) -> Dict[str, str]:
    """Parse vCard data from RDAP response"""
    if not vcard_array or len(vcard_array) < 2:
        return {}

    vcard_data = {}
    for field in vcard_array[1]:
        if not isinstance(field, list) or len(field) < 4:
            continue

        field_name = field[0]
        field_value = field[3]

        if field_name == 'fn':  # Full name
            vcard_data['name'] = field_value
        elif field_name == 'email':
            vcard_data['email'] = field_value
        elif field_name == 'org':
            vcard_data['organization'] = field_value
        elif field_name == 'adr':  # Address
            vcard_data['address'] = field_value

    return vcard_data


async def lookup_rdap(domain: str) -> Dict:
    """
    Lookup domain using RDAP protocol

    Args:
        domain: Domain name to lookup

    Returns:
        Dictionary with WHOIS data
    """
    tld = extract_tld(domain)

    # Try TLD-specific RDAP server first
    rdap_url = RDAP_SERVERS.get(tld)

    if not rdap_url:
        # Fallback to RDAP bootstrap service (handles all TLDs)
        logger.info(f"No specific RDAP server for .{tld}, using bootstrap")
        rdap_url = f"https://rdap.org/domain/"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"{rdap_url}{domain}",
                headers={'Accept': 'application/json'},
                follow_redirects=True
            )

            if response.status_code == 404:
                logger.warning(f"Domain {domain} not found in RDAP")
                return {
                    'success': False,
                    'error': 'Domain not found in registry'
                }

            if response.status_code != 200:
                logger.error(f"RDAP query failed: {response.status_code}")
                return {
                    'success': False,
                    'error': f'RDAP server returned {response.status_code}'
                }

            rdap_data = response.json()

            # Parse RDAP response
            parsed_data = parse_rdap_response(rdap_data)

            return {
                'success': True,
                'data': parsed_data
            }

    except httpx.TimeoutException:
        logger.error(f"RDAP timeout for {domain}")
        return {
            'success': False,
            'error': 'RDAP query timeout'
        }
    except Exception as e:
        logger.error(f"RDAP error for {domain}: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }


def parse_rdap_response(rdap_data: Dict) -> Dict:
    """
    Parse RDAP JSON response into normalized WHOIS data

    Args:
        rdap_data: Raw RDAP response

    Returns:
        Normalized WHOIS data dictionary
    """
    result = {
        'registrant': {},
        'registrar': '',
        'nameservers': [],
        'created': '',
        'updated': '',
        'expires': '',
        'emails': [],
        'organization': '',
        'status': []
    }

    # Extract entities (registrant, registrar, etc.)
    entities = rdap_data.get('entities', [])

    for entity in entities:
        roles = entity.get('roles', [])
        vcard = parse_vcard(entity.get('vcardArray'))

        if 'registrant' in roles:
            result['registrant'] = vcard
            if 'organization' in vcard:
                result['organization'] = vcard['organization']

        if 'registrar' in roles:
            if 'name' in vcard:
                result['registrar'] = vcard['name']

        # Extract emails from all entities
        if 'email' in vcard:
            result['emails'].append(vcard['email'])

    # Extract nameservers
    nameservers = rdap_data.get('nameservers', [])
    result['nameservers'] = [
        ns.get('ldhName', '') for ns in nameservers
    ]

    # Extract dates
    events = rdap_data.get('events', [])
    for event in events:
        action = event.get('eventAction')
        date = event.get('eventDate', '')

        if action == 'registration':
            result['created'] = date
        elif action == 'last changed' or action == 'last update of RDAP database':
            result['updated'] = date
        elif action == 'expiration':
            result['expires'] = date

    # Extract status
    status = rdap_data.get('status', [])
    result['status'] = status

    # Remove duplicates from emails
    result['emails'] = list(set(result['emails']))

    return result


# For backward compatibility with existing code
async def lookup_whois(domain: str) -> Dict:
    """
    Lookup WHOIS data for domain using RDAP
    (Wrapper for backward compatibility)
    """
    return await lookup_rdap(domain)
