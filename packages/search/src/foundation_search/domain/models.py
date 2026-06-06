"""Search models."""
from __future__ import annotations
from datetime import datetime; from typing import Any
from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from foundation_search.domain.base import Base

class SearchIndex(Base):
    __tablename__ = "search_index"
    __table_args__ = (Index("si_tenant_type_idx", "tenant_id", "resource_type"), {"schema": "search"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(32), nullable=False)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    acl_user_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    # M2: ACL expansion fields
    acl_team_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    owner_id: Mapped[str | None] = mapped_column(String(64))
    visibility: Mapped[str | None] = mapped_column(String(30))  # "PUBLIC_IN_TENANT" | "PRIVATE" | etc.
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    indexed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class SearchQueryLog(Base):
    __tablename__ = "search_query_log"
    __table_args__ = ({"schema": "search"},)
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False)
    query: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[str | None] = mapped_column(String(30))
    result_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    searched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class Outbox(Base):
    __tablename__ = "search_event_outbox"
    __table_args__ = ({"schema": "search"},)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
