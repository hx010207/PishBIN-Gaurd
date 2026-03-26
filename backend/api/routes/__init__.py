from fastapi import APIRouter
from . import analyzer

api_router = APIRouter()
api_router.include_router(analyzer.router, tags=["Analyzer"])
