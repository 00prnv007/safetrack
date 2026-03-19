import httpx
from bs4 import BeautifulSoup
from utils.logger import logger
from config import Config

async def analyze_content(url: str) -> dict:
    """Fetch URL and analyze the HTML content."""
    logger.debug(f"Running Content analysis for {url}")
    
    suspicious_patterns = []
    score_penalty = 0
    
    try:
        async with httpx.AsyncClient(timeout=Config.TIMEOUT, follow_redirects=True) as client:
            # We use a standard user-agent to pretend we are a browser
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            response = await client.get(url, headers=headers)
            
            # Check content type
            if "text/html" not in response.headers.get("Content-Type", "").lower():
                return {"score_penalty": 0, "reasons": []} # Not HTML, skip
                
            html = response.text
            soup = BeautifulSoup(html, "html.parser")
            
            # 1. Check for hidden iframes
            iframes = soup.find_all("iframe")
            hidden_iframes = 0
            for iframe in iframes:
                style = iframe.get("style", "").lower()
                width = iframe.get("width", "100")
                height = iframe.get("height", "100")
                if "display:none" in style or "visibility:hidden" in style or width == "0" or height == "0":
                    hidden_iframes += 1
            
            if hidden_iframes > 0:
                suspicious_patterns.append(f"Found {hidden_iframes} hidden iframe(s)")
                score_penalty += 25
                
            # 2. Check for forms asking for passwords on non-HTTPS
            if not url.startswith("https"):
                password_inputs = soup.find_all("input", type="password")
                if password_inputs:
                    suspicious_patterns.append("Password input found on non-HTTPS page")
                    score_penalty += 50
                    
            # 3. Check for suspicious scripts
            scripts = soup.find_all("script")
            external_scripts = [s for s in scripts if s.get("src")]
            # If large number of external scripts from weird domains, it could be bad, but hard to say.
            
            return {
                "score_penalty": min(score_penalty, 80),
                "reasons": suspicious_patterns
            }
            
    except httpx.RequestError as e:
        logger.warning(f"Failed to fetch content for {url}: {e}")
        return {
            "score_penalty": 10,
            "reasons": [f"Could not connect to URL to fetch content"]
        }
    except Exception as e:
        logger.error(f"Error analyzing content for {url}: {e}")
        return {"score_penalty": 0, "reasons": []}
