import httpx
import base64
from utils.logger import logger
from config import Config

def get_vt_url_id(url: str) -> str:
    """Generate the URL identifier for VT API v3."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return url_id

async def check_virustotal(url: str) -> dict:
    """Check URL against VirusTotal."""
    if not Config.VT_API_KEY:
        logger.warning("VirusTotal API Key missing.")
        return {"score_penalty": 0, "reasons": []}
        
    logger.debug(f"Checking VirusTotal for {url}")
    url_id = get_vt_url_id(url)
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    headers = {
        "x-apikey": Config.VT_API_KEY
    }
    
    try:
        async with httpx.AsyncClient(timeout=Config.TIMEOUT) as client:
            response = await client.get(api_url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                score_penalty = 0
                reasons = []
                
                if malicious > 0:
                    score_penalty += malicious * 30  # Heavy penalty for malicious hits
                    reasons.append(f"VirusTotal: {malicious} engine(s) flagged as malicious")
                if suspicious > 0:
                    score_penalty += suspicious * 10
                    reasons.append(f"VirusTotal: {suspicious} engine(s) flagged as suspicious")
                    
                return {
                    "score_penalty": min(score_penalty, 80),
                    "reasons": reasons
                }
            elif response.status_code == 404:
                # URL not found in VT database, this is fine
                return {"score_penalty": 0, "reasons": []}
            else:
                logger.warning(f"VT API Error {response.status_code}: {response.text}")
                return {"score_penalty": 0, "reasons": []}
    except Exception as e:
        logger.error(f"Error checking VT: {e}")
        return {"score_penalty": 0, "reasons": []}


async def check_google_safe_browsing(url: str) -> dict:
    """Check URL against Google Safe Browsing."""
    if not Config.GSB_API_KEY:
        logger.warning("Google Safe Browsing API Key missing.")
        return {"score_penalty": 0, "reasons": [], "threats": []}
        
    logger.debug(f"Checking Google Safe Browsing for {url}")
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={Config.GSB_API_KEY}"
    
    payload = {
        "client": {
            "clientId": "safetrace-backend",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    
    try:
        async with httpx.AsyncClient(timeout=Config.TIMEOUT) as client:
            response = await client.post(api_url, json=payload)
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get("matches", [])
                
                if matches:
                    threat_types = list(set([match["threatType"] for match in matches]))
                    return {
                        "score_penalty": 100,  # Immediate high risk
                        "reasons": [f"Google Safe Browsing flagged as: {', '.join(threat_types)}"],
                        "threats": threat_types
                    }
                return {"score_penalty": 0, "reasons": [], "threats": []}
            else:
                logger.warning(f"GSB API Error {response.status_code}: {response.text}")
                return {"score_penalty": 0, "reasons": [], "threats": []}
    except Exception as e:
        logger.error(f"Error checking GSB: {e}")
        return {"score_penalty": 0, "reasons": [], "threats": []}
