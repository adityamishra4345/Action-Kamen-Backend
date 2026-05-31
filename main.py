from dotenv import load_dotenv
load_dotenv()
from qr_shield_ai.nlp_engine import analyze_text_payload, analyze_url_payload
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from urllib.parse import urlparse
import httpx
import re

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://action-kamen-frontend.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class InspectRequest(BaseModel):
    content: str

class InspectResponse(BaseModel):
    verdict: str
    threat_score: int
    content_type: str
    redirect_chain: List[str]
    typosquat_match: Optional[str] = None
    tld_risk: bool
    apk_detected: bool
    findings: List[str]

class TextAnalyzeRequest(BaseModel):
    text: str

class TextAnalyzeResponse(BaseModel):
    verdict: str
    threat_score: int
    triggered_keywords: List[str]
    nlp_label: str
    nlp_confidence: float
    findings: List[str]

@app.post("/api/inspect", response_model=InspectResponse)
async def inspect_qr(request: InspectRequest):
    url = request.content.strip()
    
    if not url.startswith("http"):
        url = "http://" + url
        
    chain = []
    threats = []
    verdict = "SAFE"
    score = 0
    apk_detected_flag = False
    
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=5.0) as client:
            response = await client.get(url)
            
            for r in response.history:
                chain.append(str(r.request.url))
                
            chain.append(str(response.url))
            
            content_header = str(response.headers.get("Content-Type", "")).lower()
            if "application/vnd.android.package-archive" in content_header or str(response.url).endswith(".apk"):
                apk_detected_flag = True
                threats.append("Malicious APK download detected")
                verdict = "DANGEROUS"
                score += 80
                
    except Exception:
        chain = [url]
        threats.append("URL unreachable or timed out")
        verdict = "SUSPICIOUS"
        score = 50

    if len(chain) > 2:
        threats.append("Too many redirects")
        verdict = "SUSPICIOUS"
        score += 30
    
    tld_risk_flag = False
    risky_tlds = [".xyz", ".top", ".pw", ".ru", ".zip", ".click"]
    final_url = chain[-1]
    domain = urlparse(final_url).netloc
    
    for tld in risky_tlds:
        if domain.endswith(tld):
            tld_risk_flag = True
            threats.append("Risky domain extension detected")
            if verdict != "DANGEROUS":
                verdict = "SUSPICIOUS"
            score += 40
            break
            
    typosquat_match = None
    brands = ["paypal", "amazon", "google", "apple", "microsoft", "netflix"]
    
    for brand in brands:
        clean_domain = domain.replace("www.", "")
        if brand in clean_domain:
            if clean_domain != f"{brand}.com":
                typosquat_match = brand
                threats.append(f"Possible typosquatting targeting {brand}")
                verdict = "DANGEROUS"
                score += 50
                break
                
    if score > 100:
        score = 100
        
    return InspectResponse(
        verdict=verdict,
        threat_score=score,
        content_type="URL",
        redirect_chain=chain,
        typosquat_match=typosquat_match,
        tld_risk=tld_risk_flag,
        apk_detected=apk_detected_flag,
        findings=threats
    )

@app.post("/api/analyze-text", response_model=TextAnalyzeResponse)
async def analyze_text(request: TextAnalyzeRequest):
    text = request.text.lower()
    threats = []
    found_keywords = []
    score = 0
    verdict = "SAFE"
    
    phishing_keywords = [
        "urgent", "suspend", "verify", "password", "wallet", 
        "seed phrase", "login", "unauthorized", "kyc", "claim"
    ]
    
    for word in phishing_keywords:
        if re.search(r'\b' + word + r'\b', text):
            found_keywords.append(word)
            
    if len(found_keywords) > 0:
        threats.append(f"Found suspicious keywords: {', '.join(found_keywords)}")
        score += len(found_keywords) * 20
        
    ai_result = analyze_text_payload(request.text)
    nlp_label = ai_result["nlp_label"]
    nlp_confidence = ai_result["nlp_confidence"]
    
    if ai_result["threat_score"] > 0:
        score += ai_result["threat_score"]
        for ai_finding in ai_result["findings"]:
            if ai_finding not in threats:
                threats.append(ai_finding)

    if score >= 60:
        verdict = "PHISHING"
    elif score > 0:
        verdict = "SUSPICIOUS"
        
    if score > 100:
        score = 100
        
    return TextAnalyzeResponse(
        verdict=verdict,
        threat_score=score,
        triggered_keywords=found_keywords,
        nlp_label=nlp_label,
        nlp_confidence=nlp_confidence,
        findings=threats
    )

@app.post("/api/analyze-url", response_model=InspectResponse)
async def analyze_url_endpoint(request: InspectRequest):
    url = request.content.strip()
    if not url.startswith("http"):
        url = "http://" + url
        
    chain = []
    base_threats = []
    apk_detected_flag = False
    tld_risk_flag = False
    typosquat_match = None
    
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=5.0) as client:
            response = await client.get(url)
            for r in response.history:
                chain.append(str(r.request.url))
            chain.append(str(response.url))
            
            content_header = str(response.headers.get("Content-Type", "")).lower()
            if "application/vnd.android.package-archive" in content_header or str(response.url).endswith(".apk"):
                apk_detected_flag = True
                base_threats.append("Malicious APK download detected")
    except Exception:
        chain = [url]
        base_threats.append("URL unreachable or timed out")
        
    final_url = chain[-1]
    domain = urlparse(final_url).netloc
    
    risky_tlds = [".xyz", ".top", ".pw", ".ru", ".zip", ".click"]
    for tld in risky_tlds:
        if domain.endswith(tld):
            tld_risk_flag = True
            base_threats.append("Risky domain extension detected")
            break
            
    brands = ["paypal", "amazon", "google", "apple", "microsoft", "netflix"]
    for brand in brands:
        clean_domain = domain.replace("www.", "")
        if brand in clean_domain and clean_domain != f"{brand}.com":
            typosquat_match = brand
            base_threats.append(f"Possible typosquatting targeting {brand}")
            break
            
    ai_result = analyze_url_payload(url)
    
    combined_score = ai_result["threat_score"]
    if apk_detected_flag: combined_score += 80
    if tld_risk_flag: combined_score += 40
    if typosquat_match: combined_score += 50
    if len(chain) > 2: combined_score += 30
    
    final_score = min(combined_score, 100)
    final_verdict = ai_result["verdict"]
    
    if final_score >= 80 or apk_detected_flag or typosquat_match:
        final_verdict = "DANGEROUS"
    elif final_score >= 50 and final_verdict == "SAFE":
        final_verdict = "SUSPICIOUS"
        
    all_findings = base_threats + ai_result["findings"]
    
    return InspectResponse(
        verdict=final_verdict,
        threat_score=final_score,
        content_type="URL AI Audit",
        redirect_chain=chain,
        typosquat_match=typosquat_match,
        tld_risk=tld_risk_flag,
        apk_detected=apk_detected_flag,
        findings=list(set(all_findings))
    )