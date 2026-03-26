import asyncio
from core.database import init_db

async def main():
    print("Initializing Database...")
    await init_db()
    print("Database Initialized.")

if __name__ == "__main__":
    asyncio.run(main())
