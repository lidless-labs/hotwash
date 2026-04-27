"""
SQLAlchemy ORM models for Hotwash.

Tables: Playbook, Tag, PlaybookTag, PlaybookVersion, Execution, ExecutionEvent,
WazuhMapping, IngestSuggestion, IngestSuppressionLog
"""

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


class Base(DeclarativeBase):
    pass


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    content_markdown: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    graph_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    share_token: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, unique=True, index=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    tags: Mapped[List["Tag"]] = relationship(
        "Tag",
        secondary="playbook_tags",
        back_populates="playbooks",
        passive_deletes=True,
    )
    versions: Mapped[List["PlaybookVersion"]] = relationship(
        "PlaybookVersion",
        back_populates="playbook",
        cascade="all, delete-orphan",
        order_by="PlaybookVersion.version_number.desc()",
    )

    __table_args__ = (
        Index("ix_playbooks_category", "category"),
        Index("ix_playbooks_is_deleted", "is_deleted"),
        Index("ix_playbooks_title", "title"),
    )

    def __repr__(self) -> str:
        return f"<Playbook(id={self.id}, title={self.title!r})>"


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    playbooks: Mapped[List["Playbook"]] = relationship(
        "Playbook",
        secondary="playbook_tags",
        back_populates="tags",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<Tag(id={self.id}, name={self.name!r})>"


class PlaybookTag(Base):
    __tablename__ = "playbook_tags"

    playbook_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("playbooks.id", ondelete="CASCADE"),
        primary_key=True,
    )
    tag_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("tags.id", ondelete="CASCADE"),
        primary_key=True,
    )

    __table_args__ = (
        Index("ix_playbook_tags_tag_id", "tag_id"),
    )


class PlaybookVersion(Base):
    __tablename__ = "playbook_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    playbook_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("playbooks.id", ondelete="CASCADE"),
        nullable=False,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    content_markdown: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    graph_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    change_summary: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    # Relationships
    playbook: Mapped["Playbook"] = relationship("Playbook", back_populates="versions")

    __table_args__ = (
        UniqueConstraint("playbook_id", "version_number", name="uq_playbook_version"),
        Index("ix_playbook_versions_playbook_id", "playbook_id"),
    )

    def __repr__(self) -> str:
        return f"<PlaybookVersion(playbook_id={self.playbook_id}, v={self.version_number})>"


class Execution(Base):
    __tablename__ = "executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    playbook_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("playbooks.id"),
        nullable=False,
    )
    incident_title: Mapped[str] = mapped_column(String(255), nullable=False)
    incident_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active", server_default="active", nullable=False)
    started_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    context_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    steps_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    playbook: Mapped["Playbook"] = relationship("Playbook")
    events: Mapped[List["ExecutionEvent"]] = relationship(
        "ExecutionEvent",
        back_populates="execution",
        cascade="all, delete-orphan",
        order_by="ExecutionEvent.timestamp.desc()",
    )

    __table_args__ = (
        Index("ix_executions_status", "status"),
        Index("ix_executions_playbook_id", "playbook_id"),
    )

    def __repr__(self) -> str:
        return f"<Execution(id={self.id}, status={self.status!r})>"


class ExecutionEvent(Base):
    __tablename__ = "execution_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    execution_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("executions.id", ondelete="CASCADE"),
        nullable=False,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    execution: Mapped["Execution"] = relationship("Execution", back_populates="events")

    __table_args__ = (
        Index("ix_execution_events_execution_id", "execution_id"),
        Index("ix_execution_events_event_type", "event_type"),
    )


class WazuhMapping(Base):
    __tablename__ = "wazuh_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    playbook_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("playbooks.id"),
        nullable=False,
    )
    mode: Mapped[str] = mapped_column(String(16), default="suggest", server_default="suggest", nullable=False)
    rule_id_pattern: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    rule_groups_pattern: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    agent_name_pattern: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=300, server_default="300", nullable=False)
    hmac_secret_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    playbook: Mapped["Playbook"] = relationship("Playbook")

    __table_args__ = (
        Index("ix_wazuh_mappings_enabled", "enabled"),
        Index("ix_wazuh_mappings_playbook_id", "playbook_id"),
    )

    def __repr__(self) -> str:
        return f"<WazuhMapping(id={self.id}, name={self.name!r}, mode={self.mode!r})>"


class IngestSuggestion(Base):
    __tablename__ = "ingest_suggestions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mapping_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("wazuh_mappings.id"),
        nullable=False,
    )
    playbook_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("playbooks.id"),
        nullable=False,
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    alert_payload_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    agent_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending", nullable=False)
    accepted_execution_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("executions.id"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    mapping: Mapped["WazuhMapping"] = relationship("WazuhMapping")
    playbook: Mapped["Playbook"] = relationship("Playbook")

    __table_args__ = (
        Index("ix_ingest_suggestions_state", "state"),
        Index("ix_ingest_suggestions_fingerprint", "fingerprint"),
    )

    def __repr__(self) -> str:
        return f"<IngestSuggestion(id={self.id}, state={self.state!r})>"


class IngestSuppressionLog(Base):
    """Append-only log of every ingest decision: dispatch, suggest, or suppress.

    Doubles as the cooldown anchor: cooldown lookups query MAX(created_at)
    WHERE fingerprint=? to find the last time this fingerprint was seen
    regardless of outcome.
    """

    __tablename__ = "ingest_suppression_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mapping_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("wazuh_mappings.id"),
        nullable=True,
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    reason: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_ingest_supp_fp_time", "fingerprint", "created_at"),
        Index("ix_ingest_supp_mapping_id", "mapping_id"),
    )

    def __repr__(self) -> str:
        return f"<IngestSuppressionLog(id={self.id}, reason={self.reason!r})>"


# Import Integration so it shares the same Base.metadata
from api.integrations.config import Integration  # noqa: E402, F401
