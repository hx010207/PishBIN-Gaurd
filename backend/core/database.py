from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql+asyncpg://postgres:phishbin_secure@localhost:5432/phishbin")

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()

async def get_db():
    try:
        async with AsyncSessionLocal() as session:
            yield session
    except Exception as e:
        print(f"Skipping native DB: {str(e)}")
        class MockSession:
            def add(self, item): pass
            async def commit(self): pass
            async def close(self): pass
        yield MockSession()

async def init_db():
    async with engine.begin() as conn:
        # await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
