import dns.resolver
import dns.exception
from typing import Dict, Any, List

async def perform_dns_lookup(domain: str) -> Dict[str, Any]:
    """
    Perform comprehensive DNS lookups for a domain

    Args:
        domain: The domain to look up

    Returns:
        Dictionary containing DNS records for various record types
    """
    results = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": [],
        "SOA": []
    }

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)

            if record_type == "MX":
                # MX records have priority and exchange
                results[record_type] = [
                    {
                        "priority": record.preference,
                        "exchange": str(record.exchange).rstrip('.')
                    }
                    for record in answers
                ]
            elif record_type == "SOA":
                # SOA records have multiple fields
                for record in answers:
                    results[record_type].append({
                        "mname": str(record.mname).rstrip('.'),
                        "rname": str(record.rname).rstrip('.'),
                        "serial": record.serial,
                        "refresh": record.refresh,
                        "retry": record.retry,
                        "expire": record.expire,
                        "minimum": record.minimum
                    })
            elif record_type == "TXT":
                # TXT records can have multiple strings
                results[record_type] = [
                    " ".join([s.decode() if isinstance(s, bytes) else s for s in record.strings])
                    for record in answers
                ]
            else:
                # A, AAAA, NS, CNAME records
                results[record_type] = [
                    str(record).rstrip('.')
                    for record in answers
                ]

        except dns.resolver.NXDOMAIN:
            # Domain does not exist
            results[record_type] = {"error": "Domain does not exist"}
        except dns.resolver.NoAnswer:
            # No records of this type
            results[record_type] = []
        except dns.resolver.NoNameservers:
            results[record_type] = {"error": "No nameservers available"}
        except dns.exception.Timeout:
            results[record_type] = {"error": "DNS query timeout"}
        except Exception as e:
            results[record_type] = {"error": str(e)}

    return results
