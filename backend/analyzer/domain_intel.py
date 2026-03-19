from utils.logger import logger

async def analyze_domain(domain: str) -> dict:
    """Analyze the domain reputation and intelligence."""
    logger.debug(f"Running Domain intelligence for {domain}")
    
    # This is a simplified version. In a real world scenario, 
    # this would query WHOIS data or a domain reputation API.
    
    suspicious_patterns = []
    score_penalty = 0
    
    # 1. Suspicious TLDs often used for spam/phishing
    suspicious_tlds = [".xyz", ".top", ".club", ".online", ".site", ".pw", ".cc", ".tk", ".ml", ".ga", ".cf", ".gq"]
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            suspicious_patterns.append(f"Suspicious Top-Level Domain (TLD) used: {tld}")
            score_penalty += 20
            break
            
    # 2. Check for typosquatting (very basic check)
    popular_domains = ["google.com", "facebook.com", "apple.com", "microsoft.com", "amazon.com", "netflix.com", "paypal.com"]
    # Check if domain is 'close' to a popular domain but not exact
    for pd in popular_domains:
        if pd in domain and domain != pd:
            suspicious_patterns.append(f"Potential typosquatting of {pd}")
            score_penalty += 40
            break
            
    return {
        "score_penalty": min(score_penalty, 60),
        "reasons": suspicious_patterns
    }
