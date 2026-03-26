from sqlalchemy import Column, Integer, String, JSON, DateTime, Float
from core.database import Base
from datetime import datetime
import uuid

class AnalysisReport(Base):
    __tablename__ = "analysis_reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String, index=True) # URL or filename
    analysis_type = Column(String) # "url" or "file"
    
    # Ultimate Engine Scores
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String)
    verdict = Column(String)
    
    # Detailed Data (Stored as JSONB in Postgres ideally, JSON here for compatibility)
    sources = Column(JSON, default=list)
    indicators = Column(JSON, default=list)
    mitigations = Column(JSON, default=list)
    evidence = Column(JSON, default=dict)
    
    created_at = Column(DateTime, default=datetime.utcnow)
