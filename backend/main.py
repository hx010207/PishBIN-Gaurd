from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os

from api.routes import analyzer

# Optional: Redis rate limiting (graceful fallback if Redis not available)
try:
    import redis.asyncio as redis
    from fastapi_limiter import FastAPILimiter
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

# Optional: Prometheus metrics (graceful fallback)
try:
    from prometheus_fastapi_instrumentator import Instrumentator
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    if HAS_REDIS:
        try:
            redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/1")
            app.state.redis = redis.from_url(redis_url, encoding="utf-8", decode_responses=True)
            await app.state.redis.ping()
            await FastAPILimiter.init(app.state.redis)
            print("Redis connected & Rate Limiting initialized.")
        except Exception as e:
            print(f"Redis not available, rate limiting disabled. Error: {e}")
            app.state.redis = None
    else:
        app.state.redis = None
        print("fastapi-limiter not installed, rate limiting skipped.")
    yield
    # Shutdown
    if getattr(app.state, "redis", None):
        await app.state.redis.close()

app = FastAPI(title="Phishbin Guard Ultimate Edition", lifespan=lifespan)

# Prometheus Metrics
if HAS_PROMETHEUS:
    Instrumentator().instrument(app).expose(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyzer.router, prefix="/api/v1")

@app.get("/")
async def health_check():
    return {"status": "ok", "version": "v2.ultimate"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
