import motor.motor_asyncio
import os

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)
db = client.phishbin
analysis_collection = db.get_collection("analyses")
