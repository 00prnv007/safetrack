from utils.logger import logger

def calculate_risk_score(results: list) -> dict:
    """Combine results from all analyzers to calculate finding."""
    logger.debug("Calculating final risk score")
    
    total_penalty = 0
    all_reasons = []
    all_threats = []
    
    for result in results:
        # Ignore None or empty results if a check failed
        if not result:
            continue
            
        penalty = result.get("score_penalty", 0)
        total_penalty += penalty
        
        reasons = result.get("reasons", [])
        if reasons:
            all_reasons.extend(reasons)
            
        threats = result.get("threats", [])
        if threats:
            all_threats.extend(threats)
            
    # Base score is 0 (safe) to 100 (dangerous)
    # The more penalties, the higher the score (worse)
    final_score = min(total_penalty, 100)
    
    # Determine risk level
    if final_score < 30:
        risk_level = "Low"
        safe = True
        message = "Link is structurally safe and no immediate threats found."
    elif final_score < 70:
        risk_level = "Medium"
        safe = False
        message = "Suspicious link detected. Proceed with caution."
    else:
        risk_level = "High"
        safe = False
        message = "Dangerous link detected! Do not visit."
        
    # Frontend expects specific format
    response = {
        "safe": safe,
        "score": final_score,
        "message": message,
        "reasons": all_reasons
    }
    
    if not safe:
        response["risk_level"] = risk_level
        if all_threats:
            response["threats"] = all_threats
            
    return response
