"""Base model with audit fields shared by all mutable documents."""

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditMixin(BaseModel):
    """Audit metadata present on every mutable MongoDB document."""
    created_at: Optional[str] = Field(default_factory=utc_now)
    created_by: str = ""
    updated_at: Optional[str] = Field(default_factory=utc_now)
    updated_by: str = ""
