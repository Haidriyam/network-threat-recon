import socket
import ssl
from datetime import datetime
import dns.resolver

def inspect_tls(domain: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (not_after - datetime.utcnow()).days
            
            return {
                "issuer": dict(x[0] for x in cert['issuer']),
                "subject": dict(x[0] for x in cert['subject']),
                "days_until_expiry": days_left,
                "san": [entry[1] for entry in cert.get('subjectAltName', []) if entry[0] == 'DNS']
            }

def inspect_dns(domain: str) -> dict:
    records = {}
    for rtype in ['A', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=4)
            records[rtype] = [r.to_text() for r in answers]
        except Exception:
            records[rtype] = []
    return records