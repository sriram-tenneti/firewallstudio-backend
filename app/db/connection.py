"""MongoDB connection management using Motor (async driver).

Provides singleton client/db accessors and startup/shutdown hooks.
"""

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.config import settings

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


def get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(settings.mongodb_uri)
    return _client


def get_db() -> AsyncIOMotorDatabase:
    global _db
    if _db is None:
        _db = get_client()[settings.mongodb_database]
    return _db


async def close_connection() -> None:
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None
