from fastapi import APIRouter, File, UploadFile, Request, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uuid

# Internal Services
from services.local_url import analyze_url_local
from services.local_binary import analyze_pe_local
from services.external_apis import get_all_url_intelligence
from services.scoring import calculate_ultimate_score
from core.database import get_db, AsyncSession
from models.report import AnalysisReport

# Rate Limiter fallback
try:
    from fastapi_limiter.depends import RateLimiter
    rate_limiter_dep = Depends(RateLimiter(times=10, seconds=60))
except Exception:
    def mock_rate_limit(): pass
    rate_limiter_dep = Depends(mock_rate_limit)

router = APIRouter()

# Mock DB for local fast-path testing without initializing full Postgres
MOCK_REPORTS_DB = []

class UrlAnalyzeRequest(BaseModel):
    url: str
    
class AnalyzeResponse(BaseModel):
    id: str
    risk_score: float
    risk_level: str
    verdict: str
    sources: List[str]
    indicators: List[str]
    mitigations: List[str]
    evidence: Dict[str, Any]

@router.post("/analyze/url", response_model=AnalyzeResponse)
async def analyze_url_endpoint(req: UrlAnalyzeRequest, db: AsyncSession = Depends(get_db)):
    """Fast path URL analysis returning within 3 seconds."""
    # 1. Local Heuristics
    local_data = analyze_url_local(req.url)
    local_score = local_data.get('score', 0)
    
    # Extract IP if available for AbuseIPDB
    ip_address = None
    for ind in local_data.get('indicators', []):
        if "IP Address" in ind:
            from urllib.parse import urlparse
            ip_address = urlparse(req.url).netloc
            break
            
    # 2. Async API Consensus
    api_results = await get_all_url_intelligence(req.url, ip_address)
    
    # 3. Ultimate Scoring Algorithm
    final_result = calculate_ultimate_score(
        local_score=local_score,
        api_results=api_results,
        behavior_score=0,
        reputation_score=0
    )
    
    # 4. Persistence
    doc_id = str(uuid.uuid4())
    report = AnalysisReport(
        id=doc_id,
        target=req.url,
        analysis_type="url",
        risk_score=final_result["risk_score"],
        risk_level=final_result["risk_level"],
        verdict=final_result["verdict"],
        sources=final_result["sources"],
        indicators=local_data.get('indicators', []),
        mitigations=final_result["mitigations"],
        evidence={
            "local_data": local_data,
            "api_results": api_results,
            "scoring_components": final_result.get("raw_components", {})
        }
    )
    
    try:
        db.add(report)
        await db.commit()
    except Exception as e:
        print(f"Postgres not available, skipping save: {e}")
        MOCK_REPORTS_DB.append(report)
    
    # Map back to dict for response
    return {
        "id": doc_id,
        "risk_score": final_result["risk_score"],
        "risk_level": final_result["risk_level"],
        "verdict": final_result["verdict"],
        "sources": final_result["sources"],
        "indicators": local_data.get('indicators', []),
        "mitigations": final_result["mitigations"],
        "evidence": report.evidence
    }

@router.post("/analyze/file", response_model=AnalyzeResponse)
async def analyze_binary_endpoint(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    """Handles file uploads for PE/Binary analysis."""
    content = await file.read()
    
    # 1. Local Static Analysis
    local_data = analyze_pe_local(content)
    local_score = local_data.get('score', 0)
    
    # 2. Hybrid Analysis API (Placeholder synchronous stub for now, would be async in real prod)
    # File uploads to HA take time, usually offloaded to Celery.
    # For now, rely heavily on our fast local analysis.
    api_results = [{"source": "Hybrid Analysis", "verdict": "Pending Async Analysis", "score": 0}]

    # 3. Ultimate Scoring
    final_result = calculate_ultimate_score(
        local_score=local_score,
        api_results=api_results,
        behavior_score=0,
        reputation_score=0
    )
    
    doc_id = str(uuid.uuid4())
    report = AnalysisReport(
        id=doc_id,
        target=file.filename,
        analysis_type="file",
        risk_score=final_result["risk_score"],
        risk_level=final_result["risk_level"],
        verdict=final_result["verdict"],
        sources=final_result["sources"],
        indicators=local_data.get('indicators', []),
        mitigations=final_result["mitigations"],
        evidence={
            "local_data": local_data,
            "scoring_components": final_result.get("raw_components", {})
        }
    )
    
    try:
        db.add(report)
        await db.commit()
    except Exception as e:
        print(f"Postgres not available, skipping save: {e}")
        MOCK_REPORTS_DB.append(report)

    return {
        "id": doc_id,
        "risk_score": final_result["risk_score"],
        "risk_level": final_result["risk_level"],
        "verdict": final_result["verdict"],
        "sources": final_result["sources"],
        "indicators": local_data.get('indicators', []),
        "mitigations": final_result["mitigations"],
        "evidence": report.evidence
    }

@router.get("/reports")
async def get_reports(db: AsyncSession = Depends(get_db)):
    """Fetch all history of reports (mocked or real)."""
    try:
        from sqlalchemy import select
        result = await db.execute(select(AnalysisReport).order_by(AnalysisReport.created_at.desc()).limit(50))
        reports = result.scalars().all()
        # Fall back to mock DB if postgres returns empty (or not configured properly)
        if not reports and MOCK_REPORTS_DB:
            return list(reversed(MOCK_REPORTS_DB))
        return reports
    except Exception as e:
        print(f"Postgres not available, returning mocked reports: {e}")
        return list(reversed(MOCK_REPORTS_DB))
