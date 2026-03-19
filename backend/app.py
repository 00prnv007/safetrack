import asyncio
from typing import List, Dict, Any
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os

from utils.logger import logger
from utils.helpers import normalize_url, extract_domain
from analyzer.url_analyzer import analyze_url_pattern
from analyzer.domain_intel import analyze_domain
from analyzer.content_analyzer import analyze_content
from analyzer.behavior_analyzer import analyze_behavior
from analyzer.api_checker import check_virustotal, check_google_safe_browsing
from analyzer.risk_engine import calculate_risk_score

app = FastAPI(title="SafeTrace Backend")

# Allow CORS if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class CheckRequest(BaseModel):
    url: str

# Mount frontend files (we will mount the parent directory for index.html)
# Because index.html is in `d:\\safetrace\\index.html` and backend is `d:\\safetrace\\backend`
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

@app.post("/api/check")
async def check_url(request: CheckRequest):
    raw_url = request.url
    logger.info(f"Received request to check URL: {raw_url}")
    
    try:
        url = normalize_url(raw_url)
        domain = extract_domain(url)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
        
    logger.info(f"Normalized URL: {url}, Domain: {domain}")
    
    # Run parallel checks
    results = await asyncio.gather(
        analyze_url_pattern(url, domain),
        analyze_domain(domain),
        analyze_content(url),
        analyze_behavior(url),
        check_virustotal(url),
        check_google_safe_browsing(url),
        return_exceptions=True # Prevent one failing check from crashing everything
    )
    
    # Filter out exceptions and log them
    valid_results = []
    for r in results:
        if isinstance(r, Exception):
            logger.error(f"Analyzer failed with exception: {r}")
        elif r:
            valid_results.append(r)
            
    # Combine results and generate risk score
    report = calculate_risk_score(valid_results)
    
    return report

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    index_path = os.path.join(parent_dir, "index.html")
    try:
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>index.html not found</h1>", status_code=404)
