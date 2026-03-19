from urllib.parse import urlparse
import re

def normalize_url(url: str) -> str:
    """Ensure URL has scheme and is correctly formatted."""
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url  # Default to https
    
    # Basic URL structure check
    if not re.match(r'^https?://[^\s/$.?#].[^\s]*$', url, re.IGNORECASE):
        raise ValueError("Invalid URL format")
        
    return url

def extract_domain(url: str) -> str:
    """Extract full domain from URL."""
    parsed = urlparse(url)
    return parsed.netloc.split(':')[0]  # Remove port if present
