import re
from utils.logger import logger

async def analyze_url_pattern(url: str, domain: str) -> dict:
    """Analyze the URL for suspicious patterns."""
    logger.debug(f"Running URL pattern analysis for {url}")
    
    suspicious_patterns = []
    score_penalty = 0
    
    # 1. Check for IP address instead of domain
    if re.match(r"^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$", domain):
        suspicious_patterns.append("IP address used instead of domain name")
        score_penalty += 30
    
    # 2. Check for unusually long URL
    if len(url) > 100:
        suspicious_patterns.append("Unusually long URL length")
        score_penalty += 10
        
    # 3. Check for multiple subdomains (e.g., a.b.c.d.example.com)
    parts = domain.split(".")
    if len(parts) > 3 and not (domain.endswith("co.uk") or domain.endswith("com.au")):
        suspicious_patterns.append("Multiple subdomains detected")
        score_penalty += 15
        
    # 4. Check for suspicious keywords in URL (phishing indicators)
    keywords = ["login", "verify", "secure", "account", "update", "bank", "paypal", "admin", "free"]
    url_lower = url.lower()
    found_keywords = [kw for kw in keywords if kw in url_lower]
    # If it's a known domain, these keywords are fine, but we will penalize if domain is fishy later.
    if found_keywords and len(parts) > 2:
        suspicious_patterns.append(f"Suspicious keywords in URL: {', '.join(found_keywords)}")
        score_penalty += 15
        
    # 5. Check for @ symbol (basic auth masking)
    if "@" in url.split("://")[-1]:
        suspicious_patterns.append("URL contains '@' symbol (user info masking)")
        score_penalty += 25
        
    return {
        "score_penalty": min(score_penalty, 60),  # Cap the penalty
        "reasons": suspicious_patterns
    }
