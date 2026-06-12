"""DataStore abstraction — switchable between JSON files and MongoDB.

Usage:
    from app.db.store import get_store
    store = get_store()

    # CRUD — same API regardless of backend
    docs = await store.find("groups", {"group_type": "ingress"})
    doc  = await store.find_one("applications", {"_id": "APP-123"})
    await store.insert_one("requests", {...})
    await store.update_one("groups", {"_id": id}, {"$set": {...}})
    await store.delete_one("requests", {"_id": id})

Config switch:
    DATA_STORE=json   → reads/writes JSON files in data/ directory
    DATA_STORE=mongodb → uses Motor async MongoDB driver

The JSON store keeps data in memory and persists to disk on every write,
making it suitable for development without a running MongoDB instance.
"""

from __future__ import annotations

import json
import os
import uuid
from abc import ABC, abstractmethod
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import settings

# ---- Collection → JSON filename mapping ----
# Each consolidated collection maps to one JSON file in data/

COLLECTION_FILES: dict[str, str] = {
    "applications": "applications.json",
    "groups": "groups.json",
    "requests": "requests.json",
    "compiled_rules": "compiled_rules.json",
    "reference_data": "reference_data.json",
    "request_status_history": "request_status_history.json",
    "audit_trail": "audit_trail.json",
    "reviews": "reviews.json",
    "migrations": "migrations.json",
    "shared_services": "shared_services.json",
}


class DataStore(ABC):
    """Abstract interface for data persistence."""

    @abstractmethod
    async def find(
        self, collection: str, query: dict | None = None,
        limit: int = 500, skip: int = 0,
        sort: list[tuple[str, int]] | None = None,
    ) -> list[dict]:
        ...

    @abstractmethod
    async def find_one(self, collection: str, query: dict) -> dict | None:
        ...

    @abstractmethod
    async def insert_one(self, collection: str, document: dict) -> str:
        ...

    @abstractmethod
    async def insert_many(self, collection: str, documents: list[dict]) -> list[str]:
        ...

    @abstractmethod
    async def update_one(
        self, collection: str, query: dict, update: dict, upsert: bool = False,
    ) -> int:
        ...

    @abstractmethod
    async def update_many(self, collection: str, query: dict, update: dict) -> int:
        ...

    @abstractmethod
    async def delete_one(self, collection: str, query: dict) -> int:
        ...

    @abstractmethod
    async def delete_many(self, collection: str, query: dict) -> int:
        ...

    @abstractmethod
    async def count(self, collection: str, query: dict | None = None) -> int:
        ...

    @abstractmethod
    async def distinct(self, collection: str, field: str, query: dict | None = None) -> list:
        ...

    @abstractmethod
    async def aggregate(self, collection: str, pipeline: list[dict]) -> list[dict]:
        ...


# ---- JSON File Store ----

def _matches(doc: dict, query: dict) -> bool:
    """Simple query matcher supporting basic MongoDB-style operators."""
    for key, val in query.items():
        if key == "$or":
            if not any(_matches(doc, sub) for sub in val):
                return False
            continue
        if key == "$and":
            if not all(_matches(doc, sub) for sub in val):
                return False
            continue

        # Nested dot notation: "members.value"
        doc_val = doc
        for part in key.split("."):
            if isinstance(doc_val, dict):
                doc_val = doc_val.get(part)
            elif isinstance(doc_val, list) and part.isdigit():
                idx = int(part)
                doc_val = doc_val[idx] if idx < len(doc_val) else None
            else:
                doc_val = None
                break

        if isinstance(val, dict):
            # Operator queries: $in, $ne, $exists, $regex, $gt, $gte, $lt, $lte
            for op, operand in val.items():
                if op == "$in":
                    if doc_val not in operand:
                        return False
                elif op == "$nin":
                    if doc_val in operand:
                        return False
                elif op == "$ne":
                    if doc_val == operand:
                        return False
                elif op == "$exists":
                    if operand and doc_val is None:
                        return False
                    if not operand and doc_val is not None:
                        return False
                elif op == "$regex":
                    import re
                    flags = re.IGNORECASE if val.get("$options", "") == "i" else 0
                    if not doc_val or not re.search(operand, str(doc_val), flags):
                        return False
                elif op == "$gt":
                    if doc_val is None or doc_val <= operand:
                        return False
                elif op == "$gte":
                    if doc_val is None or doc_val < operand:
                        return False
                elif op == "$lt":
                    if doc_val is None or doc_val >= operand:
                        return False
                elif op == "$lte":
                    if doc_val is None or doc_val > operand:
                        return False
        else:
            if doc_val != val:
                return False
    return True


def _apply_update(doc: dict, update: dict) -> dict:
    """Apply MongoDB-style $set / $unset / $push / $inc / $addToSet to a doc."""
    result = deepcopy(doc)

    if "$set" in update:
        for key, val in update["$set"].items():
            parts = key.split(".")
            target = result
            for p in parts[:-1]:
                if p not in target:
                    target[p] = {}
                target = target[p]
            target[parts[-1]] = val

    if "$unset" in update:
        for key in update["$unset"]:
            parts = key.split(".")
            target = result
            for p in parts[:-1]:
                if isinstance(target, dict) and p in target:
                    target = target[p]
                else:
                    target = None
                    break
            if isinstance(target, dict) and parts[-1] in target:
                del target[parts[-1]]

    if "$inc" in update:
        for key, val in update["$inc"].items():
            parts = key.split(".")
            target = result
            for p in parts[:-1]:
                target = target.setdefault(p, {})
            target[parts[-1]] = (target.get(parts[-1]) or 0) + val

    if "$push" in update:
        for key, val in update["$push"].items():
            parts = key.split(".")
            target = result
            for p in parts[:-1]:
                target = target.setdefault(p, {})
            arr = target.setdefault(parts[-1], [])
            if isinstance(val, dict) and "$each" in val:
                arr.extend(val["$each"])
            else:
                arr.append(val)

    if "$addToSet" in update:
        for key, val in update["$addToSet"].items():
            parts = key.split(".")
            target = result
            for p in parts[:-1]:
                target = target.setdefault(p, {})
            arr = target.setdefault(parts[-1], [])
            items = val.get("$each", [val]) if isinstance(val, dict) and "$each" in val else [val]
            for item in items:
                if item not in arr:
                    arr.append(item)

    result["updated_at"] = datetime.now(timezone.utc).isoformat()
    return result


class JsonFileStore(DataStore):
    """In-memory store backed by JSON files in data/ directory."""

    def __init__(self, data_dir: str = "data"):
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, list[dict]] = {}

    def _load(self, collection: str) -> list[dict]:
        if collection in self._cache:
            return self._cache[collection]
        filename = COLLECTION_FILES.get(collection, f"{collection}.json")
        filepath = self._data_dir / filename
        if filepath.exists():
            with open(filepath, "r") as f:
                data = json.load(f)
                self._cache[collection] = data if isinstance(data, list) else []
        else:
            self._cache[collection] = []
        return self._cache[collection]

    def _save(self, collection: str) -> None:
        filename = COLLECTION_FILES.get(collection, f"{collection}.json")
        filepath = self._data_dir / filename
        with open(filepath, "w") as f:
            json.dump(self._cache.get(collection, []), f, indent=2, default=str)

    async def find(
        self, collection: str, query: dict | None = None,
        limit: int = 500, skip: int = 0,
        sort: list[tuple[str, int]] | None = None,
    ) -> list[dict]:
        docs = self._load(collection)
        if query:
            docs = [d for d in docs if _matches(d, query)]
        if sort:
            for key, direction in reversed(sort):
                docs.sort(key=lambda d: d.get(key, ""), reverse=(direction == -1))
        return deepcopy(docs[skip:skip + limit])

    async def find_one(self, collection: str, query: dict) -> dict | None:
        for doc in self._load(collection):
            if _matches(doc, query):
                return deepcopy(doc)
        return None

    async def insert_one(self, collection: str, document: dict) -> str:
        docs = self._load(collection)
        doc = deepcopy(document)
        if "_id" not in doc:
            doc["_id"] = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        doc.setdefault("created_at", now)
        doc.setdefault("updated_at", now)
        docs.append(doc)
        self._save(collection)
        return str(doc["_id"])

    async def insert_many(self, collection: str, documents: list[dict]) -> list[str]:
        ids = []
        for doc in documents:
            doc_id = await self.insert_one(collection, doc)
            ids.append(doc_id)
        return ids

    async def update_one(
        self, collection: str, query: dict, update: dict, upsert: bool = False,
    ) -> int:
        docs = self._load(collection)
        for i, doc in enumerate(docs):
            if _matches(doc, query):
                docs[i] = _apply_update(doc, update)
                self._save(collection)
                return 1
        if upsert:
            new_doc = dict(query)
            new_doc = _apply_update(new_doc, update)
            if "_id" not in new_doc:
                new_doc["_id"] = str(uuid.uuid4())
            docs.append(new_doc)
            self._save(collection)
            return 1
        return 0

    async def update_many(self, collection: str, query: dict, update: dict) -> int:
        docs = self._load(collection)
        count = 0
        for i, doc in enumerate(docs):
            if _matches(doc, query):
                docs[i] = _apply_update(doc, update)
                count += 1
        if count > 0:
            self._save(collection)
        return count

    async def delete_one(self, collection: str, query: dict) -> int:
        docs = self._load(collection)
        for i, doc in enumerate(docs):
            if _matches(doc, query):
                docs.pop(i)
                self._save(collection)
                return 1
        return 0

    async def delete_many(self, collection: str, query: dict) -> int:
        docs = self._load(collection)
        original = len(docs)
        self._cache[collection] = [d for d in docs if not _matches(d, query)]
        removed = original - len(self._cache[collection])
        if removed > 0:
            self._save(collection)
        return removed

    async def count(self, collection: str, query: dict | None = None) -> int:
        docs = self._load(collection)
        if query:
            return sum(1 for d in docs if _matches(d, query))
        return len(docs)

    async def distinct(self, collection: str, field: str, query: dict | None = None) -> list:
        docs = self._load(collection)
        if query:
            docs = [d for d in docs if _matches(d, query)]
        seen: set = set()
        result: list = []
        for d in docs:
            val = d.get(field)
            if val is not None and val not in seen:
                seen.add(val)
                result.append(val)
        return result

    async def aggregate(self, collection: str, pipeline: list[dict]) -> list[dict]:
        docs = self._load(collection)
        result = deepcopy(docs)
        for stage in pipeline:
            if "$match" in stage:
                result = [d for d in result if _matches(d, stage["$match"])]
            elif "$sort" in stage:
                for key, direction in reversed(list(stage["$sort"].items())):
                    result.sort(key=lambda d: d.get(key, ""), reverse=(direction == -1))
            elif "$limit" in stage:
                result = result[:stage["$limit"]]
            elif "$skip" in stage:
                result = result[stage["$skip"]:]
            elif "$group" in stage:
                # Basic $group with $sum / $count
                group_spec = stage["$group"]
                group_key = group_spec.get("_id")
                groups: dict[str, dict] = {}
                for d in result:
                    gk = str(d.get(group_key.lstrip("$"), "")) if isinstance(group_key, str) and group_key.startswith("$") else str(group_key)
                    if gk not in groups:
                        groups[gk] = {"_id": gk}
                    for acc_name, acc_op in group_spec.items():
                        if acc_name == "_id":
                            continue
                        if isinstance(acc_op, dict):
                            if "$sum" in acc_op:
                                groups[gk][acc_name] = groups[gk].get(acc_name, 0) + 1
                result = list(groups.values())
        return result

    async def load_from_files(self) -> dict[str, int]:
        """Reload all collections from disk. Returns {collection: count}."""
        self._cache.clear()
        counts = {}
        for coll_name in COLLECTION_FILES:
            docs = self._load(coll_name)
            counts[coll_name] = len(docs)
        return counts


# ---- MongoDB Store ----

class MongoStore(DataStore):
    """MongoDB store using Motor async driver."""

    async def find(
        self, collection: str, query: dict | None = None,
        limit: int = 500, skip: int = 0,
        sort: list[tuple[str, int]] | None = None,
    ) -> list[dict]:
        from app.db.connection import get_db
        coll = get_db()[collection]
        cursor = coll.find(query or {})
        if sort:
            cursor = cursor.sort(sort)
        cursor = cursor.skip(skip).limit(limit)
        return await cursor.to_list(length=limit)

    async def find_one(self, collection: str, query: dict) -> dict | None:
        from app.db.connection import get_db
        return await get_db()[collection].find_one(query)

    async def insert_one(self, collection: str, document: dict) -> str:
        from app.db.connection import get_db
        now = datetime.now(timezone.utc).isoformat()
        document.setdefault("created_at", now)
        document.setdefault("updated_at", now)
        result = await get_db()[collection].insert_one(document)
        return str(result.inserted_id)

    async def insert_many(self, collection: str, documents: list[dict]) -> list[str]:
        from app.db.connection import get_db
        now = datetime.now(timezone.utc).isoformat()
        for doc in documents:
            doc.setdefault("created_at", now)
            doc.setdefault("updated_at", now)
        result = await get_db()[collection].insert_many(documents)
        return [str(oid) for oid in result.inserted_ids]

    async def update_one(
        self, collection: str, query: dict, update: dict, upsert: bool = False,
    ) -> int:
        from app.db.connection import get_db
        if "$set" in update:
            update["$set"]["updated_at"] = datetime.now(timezone.utc).isoformat()
        result = await get_db()[collection].update_one(query, update, upsert=upsert)
        return result.modified_count

    async def update_many(self, collection: str, query: dict, update: dict) -> int:
        from app.db.connection import get_db
        if "$set" in update:
            update["$set"]["updated_at"] = datetime.now(timezone.utc).isoformat()
        result = await get_db()[collection].update_many(query, update)
        return result.modified_count

    async def delete_one(self, collection: str, query: dict) -> int:
        from app.db.connection import get_db
        result = await get_db()[collection].delete_one(query)
        return result.deleted_count

    async def delete_many(self, collection: str, query: dict) -> int:
        from app.db.connection import get_db
        result = await get_db()[collection].delete_many(query)
        return result.deleted_count

    async def count(self, collection: str, query: dict | None = None) -> int:
        from app.db.connection import get_db
        return await get_db()[collection].count_documents(query or {})

    async def distinct(self, collection: str, field: str, query: dict | None = None) -> list:
        from app.db.connection import get_db
        return await get_db()[collection].distinct(field, query or {})

    async def aggregate(self, collection: str, pipeline: list[dict]) -> list[dict]:
        from app.db.connection import get_db
        cursor = get_db()[collection].aggregate(pipeline)
        return await cursor.to_list(length=1000)


# ---- Singleton ----

_store: DataStore | None = None


def get_store() -> DataStore:
    """Get the configured data store instance."""
    global _store
    if _store is None:
        if settings.data_store == "mongodb":
            _store = MongoStore()
        else:
            _store = JsonFileStore(data_dir=settings.json_data_dir)
    return _store


def reset_store() -> None:
    """Reset the singleton (useful for testing or switching modes)."""
    global _store
    _store = None
