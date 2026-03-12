"""Shared tag normalization and lookup helpers."""

from sqlalchemy.orm import Session

from api.orm_models import Tag


def normalize_tag(name: str) -> str:
    return "-".join(name.strip().lower().split())


def get_or_create_tag(db: Session, name: str) -> Tag:
    normalized = normalize_tag(name)
    existing = db.query(Tag).filter(Tag.name == normalized).first()
    if existing:
        return existing
    tag = Tag(name=normalized)
    db.add(tag)
    db.flush()
    return tag
