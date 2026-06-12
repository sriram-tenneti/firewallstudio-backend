"""Consolidated MongoDB collection names (10 collections).

Optimized from 25+ collections by using type discriminators:
  - reference_data: neighbourhoods, security_zones, DCs, policy, ports, naming
  - groups: firewall + ingress (group_type discriminator)
  - requests: rule + group_change (request_type discriminator)
  - compiled_rules: physical rules for all request types
  - shared_services: shared services + ITSM connectors
  - migrations: migration data + mappings
  - reviews, request_status_history, audit_trail: standalone
  - applications: app registry + presences as nested docs

When DATA_STORE=json, col() returns a JsonCollectionProxy that mimics Motor's
AsyncIOMotorCollection API using the in-memory JsonFileStore.
"""

from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from app.config import settings

# ---- 10 Consolidated Collections ----

APPLICATIONS = "applications"
GROUPS = "groups"
REQUESTS = "requests"
COMPILED_RULES = "compiled_rules"
REFERENCE_DATA = "reference_data"
REQUEST_STATUS_HISTORY = "request_status_history"
AUDIT_TRAIL = "audit_trail"
REVIEWS = "reviews"
MIGRATIONS = "migrations"
SHARED_SERVICES = "shared_services"

# ---- Legacy aliases (map old names → new) ----
FIREWALL_GROUPS = GROUPS
INGRESS_GROUPS = GROUPS
RULE_REQUESTS = REQUESTS
GROUP_CHANGE_REQUESTS = REQUESTS
PHYSICAL_RULES = COMPILED_RULES
NEIGHBOURHOODS = REFERENCE_DATA
SECURITY_ZONES = REFERENCE_DATA
NGDC_DATACENTERS = REFERENCE_DATA
LEGACY_DATACENTERS = REFERENCE_DATA
POLICY_MATRIX = REFERENCE_DATA
PORT_CATALOG = REFERENCE_DATA
NAMING_STANDARDS = REFERENCE_DATA
ITSM_CONNECTORS = SHARED_SERVICES
MIGRATION_MAPPINGS = MIGRATIONS
APP_PRESENCES = APPLICATIONS
SHARED_SERVICE_PRESENCES = SHARED_SERVICES
ENVIRONMENTS = REFERENCE_DATA
ORG_CONFIG = REFERENCE_DATA
LIFECYCLE_EVENTS = AUDIT_TRAIL
APP_DC_MAPPINGS = REFERENCE_DATA
MIGRATION_RULE_LIFECYCLE = MIGRATIONS
CHG_REQUESTS = SHARED_SERVICES
FIREWALL_DEVICES = REFERENCE_DATA
FIREWALL_DEVICE_PATTERNS = REFERENCE_DATA
DC_VENDOR_MAP = REFERENCE_DATA
LEGACY_RULES = "compiled_rules"  # legacy rules stored in compiled_rules with rule_type


# ---- JSON Collection Proxy ----
# Mimics Motor's AsyncIOMotorCollection API for seamless route compatibility

class _InsertOneResult:
    def __init__(self, inserted_id: str):
        self.inserted_id = inserted_id


class _InsertManyResult:
    def __init__(self, inserted_ids: list[str]):
        self.inserted_ids = inserted_ids


class _UpdateResult:
    def __init__(self, modified_count: int, matched_count: int = 0, upserted_id: str | None = None):
        self.modified_count = modified_count
        self.matched_count = matched_count
        self.upserted_id = upserted_id


class _DeleteResult:
    def __init__(self, deleted_count: int):
        self.deleted_count = deleted_count


class _JsonCursor:
    """Mimics Motor's cursor with .sort(), .skip(), .limit(), .to_list()."""

    def __init__(self, docs: list[dict]):
        self._docs = docs
        self._sort_fields: list[tuple[str, int]] = []
        self._skip_val = 0
        self._limit_val = 0

    def sort(self, key_or_list, direction: int = 1):
        if isinstance(key_or_list, str):
            self._sort_fields = [(key_or_list, direction)]
        elif isinstance(key_or_list, list):
            self._sort_fields = key_or_list
        return self

    def skip(self, n: int):
        self._skip_val = n
        return self

    def limit(self, n: int):
        self._limit_val = n
        return self

    async def to_list(self, length: int | None = None) -> list[dict]:
        docs = self._docs
        if self._sort_fields:
            for key, direction in reversed(self._sort_fields):
                docs = sorted(docs, key=lambda d: d.get(key, "") or "", reverse=(direction == -1))
        if self._skip_val:
            docs = docs[self._skip_val:]
        limit = self._limit_val or length or 500
        if limit:
            docs = docs[:limit]
        return deepcopy(docs)


class JsonCollectionProxy:
    """Proxy that looks like an AsyncIOMotorCollection but reads/writes via JsonFileStore."""

    def __init__(self, collection_name: str):
        self._name = collection_name

    def _store(self):
        from app.db.store import get_store
        return get_store()

    def _get_docs(self) -> list[dict]:
        store = self._store()
        return store._load(self._name)

    def find(self, query: dict | None = None, *args, **kwargs) -> _JsonCursor:
        from app.db.store import _matches
        docs = self._get_docs()
        if query:
            docs = [d for d in docs if _matches(d, query)]
        else:
            docs = list(docs)
        return _JsonCursor(docs)

    async def find_one(self, query: dict | None = None, *args, **kwargs) -> dict | None:
        from app.db.store import _matches
        docs = self._get_docs()
        q = query or {}
        for doc in docs:
            if _matches(doc, q):
                return deepcopy(doc)
        return None

    async def insert_one(self, document: dict) -> _InsertOneResult:
        store = self._store()
        doc = deepcopy(document)
        if "_id" not in doc:
            doc["_id"] = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        doc.setdefault("created_at", now)
        doc.setdefault("updated_at", now)
        docs = store._load(self._name)
        docs.append(doc)
        store._save(self._name)
        return _InsertOneResult(str(doc["_id"]))

    async def insert_many(self, documents: list[dict]) -> _InsertManyResult:
        ids = []
        for doc in documents:
            result = await self.insert_one(doc)
            ids.append(result.inserted_id)
        return _InsertManyResult(ids)

    async def update_one(self, query: dict, update: dict, upsert: bool = False) -> _UpdateResult:
        from app.db.store import _matches, _apply_update
        store = self._store()
        docs = store._load(self._name)
        for i, doc in enumerate(docs):
            if _matches(doc, query):
                docs[i] = _apply_update(doc, update)
                store._save(self._name)
                return _UpdateResult(modified_count=1, matched_count=1)
        if upsert:
            new_doc = dict(query)
            new_doc = _apply_update(new_doc, update)
            if "_id" not in new_doc:
                new_doc["_id"] = str(uuid.uuid4())
            docs.append(new_doc)
            store._save(self._name)
            return _UpdateResult(modified_count=0, matched_count=0, upserted_id=new_doc["_id"])
        return _UpdateResult(modified_count=0, matched_count=0)

    async def update_many(self, query: dict, update: dict) -> _UpdateResult:
        from app.db.store import _matches, _apply_update
        store = self._store()
        docs = store._load(self._name)
        count = 0
        for i, doc in enumerate(docs):
            if _matches(doc, query):
                docs[i] = _apply_update(doc, update)
                count += 1
        if count > 0:
            store._save(self._name)
        return _UpdateResult(modified_count=count, matched_count=count)

    async def delete_one(self, query: dict) -> _DeleteResult:
        from app.db.store import _matches
        store = self._store()
        docs = store._load(self._name)
        for i, doc in enumerate(docs):
            if _matches(doc, query):
                docs.pop(i)
                store._save(self._name)
                return _DeleteResult(deleted_count=1)
        return _DeleteResult(deleted_count=0)

    async def delete_many(self, query: dict) -> _DeleteResult:
        from app.db.store import _matches
        store = self._store()
        docs = store._load(self._name)
        original = len(docs)
        store._cache[self._name] = [d for d in docs if not _matches(d, query)]
        removed = original - len(store._cache[self._name])
        if removed > 0:
            store._save(self._name)
        return _DeleteResult(deleted_count=removed)

    async def replace_one(self, query: dict, replacement: dict, upsert: bool = False) -> _UpdateResult:
        from app.db.store import _matches
        store = self._store()
        docs = store._load(self._name)
        for i, doc in enumerate(docs):
            if _matches(doc, query):
                rep = deepcopy(replacement)
                rep["_id"] = doc.get("_id", str(uuid.uuid4()))
                rep["updated_at"] = datetime.now(timezone.utc).isoformat()
                docs[i] = rep
                store._save(self._name)
                return _UpdateResult(modified_count=1, matched_count=1)
        if upsert:
            rep = deepcopy(replacement)
            if "_id" not in rep:
                rep["_id"] = str(uuid.uuid4())
            docs.append(rep)
            store._save(self._name)
            return _UpdateResult(modified_count=0, matched_count=0, upserted_id=rep["_id"])
        return _UpdateResult(modified_count=0, matched_count=0)

    async def count_documents(self, query: dict | None = None) -> int:
        from app.db.store import _matches
        docs = self._get_docs()
        if query:
            return sum(1 for d in docs if _matches(d, query))
        return len(docs)

    async def distinct(self, field: str, query: dict | None = None) -> list:
        from app.db.store import _matches
        docs = self._get_docs()
        if query:
            docs = [d for d in docs if _matches(d, query)]
        seen: set = set()
        result: list = []
        for d in docs:
            val = d.get(field)
            if val is not None and val not in seen:
                seen.add(val if not isinstance(val, dict) else str(val))
                result.append(val)
        return result

    def aggregate(self, pipeline: list[dict]):
        from app.db.store import _matches
        docs = deepcopy(self._get_docs())
        result = docs
        for stage in pipeline:
            if "$match" in stage:
                result = [d for d in result if _matches(d, stage["$match"])]
            elif "$sort" in stage:
                for key, direction in reversed(list(stage["$sort"].items())):
                    result.sort(key=lambda d, k=key: d.get(k, "") or "", reverse=(direction == -1))
            elif "$limit" in stage:
                result = result[:stage["$limit"]]
            elif "$skip" in stage:
                result = result[stage["$skip"]:]
            elif "$group" in stage:
                group_spec = stage["$group"]
                group_key = group_spec.get("_id")
                groups: dict[str, dict] = {}
                for d in result:
                    if isinstance(group_key, str) and group_key.startswith("$"):
                        gk = str(d.get(group_key.lstrip("$"), ""))
                    else:
                        gk = str(group_key)
                    if gk not in groups:
                        groups[gk] = {"_id": gk}
                    for acc_name, acc_op in group_spec.items():
                        if acc_name == "_id":
                            continue
                        if isinstance(acc_op, dict):
                            if "$sum" in acc_op:
                                groups[gk][acc_name] = groups[gk].get(acc_name, 0) + 1
                result = list(groups.values())
        return _JsonCursor(result)


def col(name: str) -> Any:
    """Get a collection handle — either Motor (MongoDB) or JSON proxy."""
    if settings.data_store == "json":
        return JsonCollectionProxy(name)
    else:
        from app.db.connection import get_db
        return get_db()[name]
