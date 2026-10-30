import socket
import urllib.parse
from datetime import datetime

def analyze_url_structure(url):
    """Deep inspection of URL structure, hostname, port, subdomains and DNS lookup."""
    if not url.startswith(('http://', 'https://')):
        url_to_parse = 'http://' + url
    else:
        url_to_parse = url

    parsed = urllib.parse.urlparse(url_to_parse)
    domain = parsed.netloc or parsed.path.split('/')[0]

    # DNS check simulation/attempt
    ip_address = 'Unknown'
    try:
        ip_address = socket.gethostbyname(domain.split(':')[0])
    except Exception:
        pass

    subdomains = domain.split('.')
    return {
        'scheme': parsed.scheme or 'http',
        'domain': domain,
        'path': parsed.path or '/',
        'query_params': parsed.query or 'None',
        'subdomains': subdomains[:-2] if len(subdomains) > 2 else [],
        'ip_address': ip_address,
        'has_ssl': parsed.scheme.lower() == 'https'
    }
