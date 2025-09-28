from motor.motor_asyncio import AsyncIOMotorClient

# Connexion à MongoDB
client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client.logs_db
collection = db.logs

# Création des index pour les performances
db.logs.create_index([("received_at", 1)])
db.logs.create_index([("ip_address", 1)])
db.logs.create_index([("route", 1)])

# Collection pour stocker les alertes
alerts_collection = db.alerts
