import httpx
from utils.logger import logger
from config import Config

async def analyze_behavior(url: str) -> dict:
    """Analyze behavior like redirect chaining."""
    logger.debug(f"Running Behavior simulation for {url}")
    
    suspicious_patterns = []
    score_penalty = 0
    redirect_count = 0
    
    try:
        # Don't follow redirects by default, manage them manually to count
        # or use follow_redirects=True and check response.history
        async with httpx.AsyncClient(timeout=Config.TIMEOUT, follow_redirects=True) as client:
            headers = {"User-Agent": "Mozilla/5.0"}
            response = await client.get(url, headers=headers)
            
            redirect_count = len(response.history)
            
            if redirect_count >= 3:
                suspicious_patterns.append(f"Excessive redirects: {redirect_count}")
                score_penalty += 30
                
            # If redirected from https to http
            if response.history and str(response.history[0].url).startswith("https") and not str(response.url).startswith("https"):
                suspicious_patterns.append("Redirected from HTTPS to HTTP")
                score_penalty += 50
                
            return {
                "score_penalty": min(score_penalty, 60),
                "reasons": suspicious_patterns,
                "redirects": redirect_count
            }
            
    except Exception as e:
        logger.warning(f"Error simulating behavior for {url}: {e}")
        return {"score_penalty": 0, "reasons": []}
