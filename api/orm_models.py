"""
SQLAlchemy ORM models for Playbook Forge.

Tables: Playbook, Tag, PlaybookTag, PlaybookVersion
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
