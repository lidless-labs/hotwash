"""
Playbooks Router

CRUD endpoints for playbook persistence and versioning.
"""

import json
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, func, or_
from sqlalchemy.orm import Session

from api.database import get_db
from api.orm_models import Playbook, PlaybookVersion, Tag
from api.parsers.markdown_parser import MarkdownParser
from api.schemas import (
    PlaybookCreate,
    PlaybookDetail,
    PlaybookSummary,
    PlaybookUpdate,
    PlaybookVersionOut,
    ShareResponse,
    SharedPlaybookResponse,
    TagOut,
)

router = APIRouter()


def _normalize_tag(name: str) -> str:
    return "-".join(name.strip().lower().split())


def _get_or_create_tag(db: Session, name: str) -> Tag:
    normalized = _normalize_tag(name)
    existing = db.query(Tag).filter(Tag.name == normalized).first()
    if existing:
        return existing
    tag = Tag(name=normalized)
    db.add(tag)
    db.flush()
    return tag


def _parse_graph_json(content_markdown: str) -> Dict[str, Any]:
    try:
        parser = MarkdownParser()
        graph = parser.parse(content_markdown)
        return graph.model_dump()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse content: {exc}") from exc


def _serialize_graph(graph_json: Optional[Dict[str, Any]]) -> Optional[str]:
    if graph_json is None:
        return None
    return json.dumps(graph_json)


def _deserialize_graph(graph_json: Optional[str]) -> Optional[Dict[str, Any]]:
    if not graph_json:
        return None
    try:
        return json.loads(graph_json)
    except json.JSONDecodeError:
        return None


def _node_count_from_graph(graph_json: Optional[str]) -> int:
    graph = _deserialize_graph(graph_json)
    if not graph:
        return 0
    nodes = graph.get("nodes") or []
    return len(nodes)


def _tags_out(tags: List[Tag]) -> List[TagOut]:
    return [TagOut(id=tag.id, name=tag.name) for tag in tags]


def _build_summary(playbook: Playbook) -> PlaybookSummary:
    return PlaybookSummary(
        id=playbook.id,
        title=playbook.title,
        description=playbook.description,
        category=playbook.category,
        tags=_tags_out(playbook.tags),
        node_count=_node_count_from_graph(playbook.graph_json),
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
    )


def _build_detail(playbook: Playbook) -> PlaybookDetail:
    return PlaybookDetail(
        id=playbook.id,
        title=playbook.title,
        description=playbook.description,
        category=playbook.category,
        content_markdown=playbook.content_markdown,
        graph_json=_deserialize_graph(playbook.graph_json),
        tags=_tags_out(playbook.tags),
        node_count=_node_count_from_graph(playbook.graph_json),
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
        versions_count=len(playbook.versions),
        share_token=playbook.share_token,
    )


def _ensure_playbook(db: Session, playbook_id: int) -> Playbook:
    playbook = (
        db.query(Playbook)
        .filter(Playbook.id == playbook_id, Playbook.is_deleted.is_(False))
        .first()
    )
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook


@router.post("/playbooks", response_model=PlaybookDetail, status_code=status.HTTP_201_CREATED)
def create_playbook(payload: PlaybookCreate, db: Session = Depends(get_db)):
    graph_json = _parse_graph_json(payload.content_markdown)
    playbook = Playbook(
        title=payload.title.strip(),
        description=payload.description,
        category=payload.category,
        content_markdown=payload.content_markdown,
        graph_json=_serialize_graph(graph_json),
    )

    if payload.tags:
        playbook.tags = [_get_or_create_tag(db, name) for name in payload.tags if name.strip()]

    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    return _build_detail(playbook)


@router.get("/playbooks", response_model=List[PlaybookSummary])
def list_playbooks(
    db: Session = Depends(get_db),
    category: Optional[str] = Query(default=None),
    tag: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    sort: str = Query(default="updated", pattern="^(created|updated|title)$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
):
    query = db.query(Playbook).filter(Playbook.is_deleted.is_(False))

    if category:
        query = query.filter(Playbook.category == category)

    if search:
        like_query = f"%{search}%"
        query = query.filter(
            or_(
                Playbook.title.ilike(like_query),
                Playbook.content_markdown.ilike(like_query),
            )
        )

    if tag:
        query = query.join(Playbook.tags).filter(Tag.name == _normalize_tag(tag))

    sort_column = {
        "created": Playbook.created_at,
        "updated": Playbook.updated_at,
        "title": Playbook.title,
    }.get(sort, Playbook.updated_at)

    if order == "asc":
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    playbooks = query.all()
    return [_build_summary(playbook) for playbook in playbooks]


@router.get("/playbooks/{playbook_id}", response_model=PlaybookDetail)
def get_playbook(playbook_id: int, db: Session = Depends(get_db)):
    playbook = _ensure_playbook(db, playbook_id)
    return _build_detail(playbook)


@router.put("/playbooks/{playbook_id}", response_model=PlaybookDetail)
def update_playbook(playbook_id: int, payload: PlaybookUpdate, db: Session = Depends(get_db)):
    playbook = _ensure_playbook(db, playbook_id)

    content_changed = payload.content_markdown is not None and payload.content_markdown != playbook.content_markdown

    if content_changed:
        max_version = (
            db.query(func.max(PlaybookVersion.version_number))
            .filter(PlaybookVersion.playbook_id == playbook.id)
            .scalar()
        )
        next_version = (max_version or 0) + 1
        version = PlaybookVersion(
            playbook_id=playbook.id,
            version_number=next_version,
            content_markdown=playbook.content_markdown,
            graph_json=playbook.graph_json,
            change_summary=None,
        )
        db.add(version)

        new_graph = _parse_graph_json(payload.content_markdown)
        playbook.content_markdown = payload.content_markdown
        playbook.graph_json = _serialize_graph(new_graph)

    if payload.title is not None:
        playbook.title = payload.title.strip()
    if payload.description is not None:
        playbook.description = payload.description
    if payload.category is not None:
        playbook.category = payload.category

    if payload.tags is not None:
        playbook.tags = [_get_or_create_tag(db, name) for name in payload.tags if name.strip()]

    db.commit()
    db.refresh(playbook)
    return _build_detail(playbook)


@router.delete("/playbooks/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_playbook(playbook_id: int, db: Session = Depends(get_db)):
    playbook = _ensure_playbook(db, playbook_id)
    playbook.is_deleted = True
    db.commit()
    return None


@router.post("/playbooks/{playbook_id}/duplicate", response_model=PlaybookDetail, status_code=status.HTTP_201_CREATED)
def duplicate_playbook(playbook_id: int, db: Session = Depends(get_db)):
    playbook = _ensure_playbook(db, playbook_id)

    duplicate = Playbook(
        title=f"{playbook.title} (Copy)",
        description=playbook.description,
        category=playbook.category,
        content_markdown=playbook.content_markdown,
        graph_json=playbook.graph_json,
    )
    duplicate.tags = list(playbook.tags)

    db.add(duplicate)
    db.commit()
    db.refresh(duplicate)
    return _build_detail(duplicate)


@router.get("/playbooks/{playbook_id}/versions", response_model=List[PlaybookVersionOut])
def list_versions(playbook_id: int, db: Session = Depends(get_db)):
    _ensure_playbook(db, playbook_id)
    versions = (
        db.query(PlaybookVersion)
        .filter(PlaybookVersion.playbook_id == playbook_id)
        .order_by(desc(PlaybookVersion.version_number))
        .all()
    )

    return [
        PlaybookVersionOut(
            version_number=version.version_number,
            content_markdown=version.content_markdown,
            graph_json=_deserialize_graph(version.graph_json),
            change_summary=version.change_summary,
            created_at=version.created_at,
        )
        for version in versions
    ]


@router.get("/playbooks/{playbook_id}/versions/{version_number}", response_model=PlaybookVersionOut)
def get_version(playbook_id: int, version_number: int, db: Session = Depends(get_db)):
    _ensure_playbook(db, playbook_id)
    version = (
        db.query(PlaybookVersion)
        .filter(
            PlaybookVersion.playbook_id == playbook_id,
            PlaybookVersion.version_number == version_number,
        )
        .first()
    )
    if not version:
        raise HTTPException(status_code=404, detail="Version not found")

    return PlaybookVersionOut(
        version_number=version.version_number,
        content_markdown=version.content_markdown,
        graph_json=_deserialize_graph(version.graph_json),
        change_summary=version.change_summary,
        created_at=version.created_at,
    )


@router.post("/playbooks/{playbook_id}/share", response_model=ShareResponse)
def create_share_link(playbook_id: int, db: Session = Depends(get_db)):
    playbook = _ensure_playbook(db, playbook_id)
    token = str(uuid.uuid4())
    playbook.share_token = token
    db.commit()
    return ShareResponse(share_url=f"/shared/{token}", token=token)


@router.delete("/playbooks/{playbook_id}/share", status_code=status.HTTP_204_NO_CONTENT)
def revoke_share_link(playbook_id: int, db: Session = Depends(get_db)):
    playbook = _ensure_playbook(db, playbook_id)
    playbook.share_token = None
    db.commit()
    return None


@router.get("/shared/{token}", response_model=SharedPlaybookResponse)
def get_shared_playbook(token: str, db: Session = Depends(get_db)):
    playbook = (
        db.query(Playbook)
        .filter(
            Playbook.share_token == token,
            Playbook.is_deleted.is_(False),
        )
        .first()
    )
    if not playbook:
        raise HTTPException(status_code=404, detail="Shared playbook not found")

    return SharedPlaybookResponse(**_build_detail(playbook).model_dump(), shared=True)
