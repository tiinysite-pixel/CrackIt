import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()
uri = os.environ.get("MONGO_URI")
print("Connecting to:", uri)
client = MongoClient(uri)
db = client["questionbank"]
# Try a simple command
print(db.command("ping"))
print("✅ Connection successful")