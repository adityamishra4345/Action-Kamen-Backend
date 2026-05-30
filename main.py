from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import requests
from urllib.parse import urlparse

from qr_shield_ai.nlp_engine import analyze_text_payload

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
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

    findings = []
    threat_score = 0
    redirect_chain = [url]
    typosquat = None
    
    # 1. Follow Redirects (Unravel Canva, Bitly, etc.)
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        if len(response.history) > 0:
            for resp in response.history:
                redirect_chain.append(resp.headers.get('Location', ''))
            redirect_chain.append(response.url)
            findings.append(f"Followed {len(response.history)} redirects to final destination.")
        final_url = response.url
    except Exception:
        final_url = url
        findings.append("Could not resolve URL. Potential dead link or local trap.")

    # 2. The Upgraded Typosquatting Check (Middle-Hop Catch)
    traps = {
        "goofle.com": "google.com",
        "paypa1.com": "paypal.com",
        "amaz0n.com": "amazon.com",
        "fake-pay": "paypal.com",
        "paypyt.com": "paypal.com",
        "secures-paypal.com": "paypal.com"
    }
    
    # Check EVERY single URL in the redirect chain to catch hidden traps
    for fake, real in traps.items():
        for hop_url in redirect_chain:
            if not hop_url: 
                continue 
            
            hop_domain = urlparse(hop_url).netloc.lower()
            
            if fake in hop_domain:
                typosquat = real
                threat_score += 85
                findings.append(f"CRITICAL: Typosquatting trap detected in redirect chain! ({fake} mimicking {real})")
                break # Caught it, stop checking this specific trap for other hops

    # Determine Verdict
    if threat_score >= 80:
        verdict = "DANGEROUS"
    elif threat_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
        threat_score = 5
        findings.append("Domain reputation appears clean.")

    return InspectResponse(
        verdict=verdict,
        threat_score=threat_score,
        content_type="URL",
        redirect_chain=list(dict.fromkeys(filter(None, redirect_chain))), # Remove duplicates/empty strings
        typosquat_match=typosquat,
        tld_risk=False,
        apk_detected=False,
        findings=findings
    )

@app.post("/api/analyze-text", response_model=TextAnalyzeResponse)
async def analyze_text(request: TextAnalyzeRequest):
    result = analyze_text_payload(request.text)
    return result