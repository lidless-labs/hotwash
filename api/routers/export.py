"""Export and import endpoints for playbooks."""

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy.orm import Session

from api.database import get_db
from api.orm_models import Playbook
from api.routers.playbooks import _build_detail, _deserialize_graph, _get_or_create_tag, _serialize_graph
from api.schemas import BulkImportResult, PlaybookDetail, PlaybookExport

router = APIRouter()


def _get_playbook_or_404(db: Session, playbook_id: int) -> Playbook:
    playbook = (
        db.query(Playbook)
        .filter(Playbook.id == playbook_id, Playbook.is_deleted.is_(False))
        .first()
    )
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook


def _edge_source(edge: Dict[str, Any]) -> Optional[str]:
    return edge.get("source") or edge.get("from")


def _edge_target(edge: Dict[str, Any]) -> Optional[str]:
    return edge.get("target") or edge.get("to")


def _edge_label(edge: Dict[str, Any]) -> Optional[str]:
    label = edge.get("label")
    if isinstance(label, dict):
        return label.get("text")
    if label is not None:
        return str(label)
    data = edge.get("data")
    if isinstance(data, dict) and data.get("label"):
        return str(data["label"])
    return None


def _sanitize_mermaid_id(node_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", node_id)


def _to_markdown_from_graph(graph: Dict[str, Any]) -> str:
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    node_by_id = {str(node.get("id")): node for node in nodes if node.get("id") is not None}
    outgoing: Dict[str, List[Dict[str, Any]]] = {}
    incoming: Dict[str, List[Dict[str, Any]]] = {}
    for edge in edges:
        src = _edge_source(edge)
        dst = _edge_target(edge)
        if not src or not dst:
            continue
        outgoing.setdefault(str(src), []).append(edge)
        incoming.setdefault(str(dst), []).append(edge)

    phases = [n for n in nodes if str(n.get("type", "")).lower() == "phase"]
    lines: List[str] = []

    for phase in phases:
        phase_id = str(phase.get("id"))
        phase_label = phase.get("label") or phase_id
        lines.append(f"## Phase: {phase_label}")

        for edge in outgoing.get(phase_id, []):
            child_id = str(_edge_target(edge))
            child = node_by_id.get(child_id)
            if not child:
                continue

            node_type = str(child.get("type", "")).lower()
            label = child.get("label") or child_id

            if node_type == "decision":
                lines.append(f"- Decision: {label}")
                for branch in outgoing.get(child_id, []):
                    branch_target = node_by_id.get(str(_edge_target(branch)))
                    if not branch_target:
                        continue
                    branch_label = (_edge_label(branch) or "branch").upper()
                    if branch_label not in {"YES", "NO"}:
                        branch_label = f"BRANCH ({branch_label})"
                    lines.append(f"  - {branch_label}: {branch_target.get('label') or branch_target.get('id')}")
            else:
                lines.append(f"- Step: {label}")

        lines.append("")

    if not lines:
        for node in nodes:
            node_type = str(node.get("type", "")).lower()
            label = node.get("label") or node.get("id") or "Untitled"
            if node_type == "phase":
                lines.append(f"## Phase: {label}")
            elif node_type == "decision":
                lines.append(f"- Decision: {label}")
            else:
                lines.append(f"- Step: {label}")

    return "\n".join(lines).strip()


def _to_mermaid(graph: Dict[str, Any]) -> str:
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    lines = ["flowchart TD"]
    id_map: Dict[str, str] = {}

    for node in nodes:
        raw_id = str(node.get("id"))
        if raw_id == "None":
            continue
        node_id = _sanitize_mermaid_id(raw_id)
        id_map[raw_id] = node_id
        label = (node.get("label") or raw_id).replace('"', "'")
        node_type = str(node.get("type", "step")).lower()

        if node_type == "decision":
            shape = f"{{{{{label}}}}}"
        elif node_type == "execute":
            shape = f"(({label}))"
        else:  # phase + step default
            shape = f"[{label}]"

        lines.append(f"    {node_id}{shape}")

    for edge in edges:
        src_raw = _edge_source(edge)
        dst_raw = _edge_target(edge)
        if not src_raw or not dst_raw:
            continue
        src = id_map.get(str(src_raw))
        dst = id_map.get(str(dst_raw))
        if not src or not dst:
            continue

        label = _edge_label(edge)
        if label:
            lines.append(f"    {src} -->|{label}| {dst}")
        else:
            lines.append(f"    {src} --> {dst}")

    return "\n".join(lines)


@router.get("/playbooks/{playbook_id}/export")
def export_playbook(
    playbook_id: int,
    format: str = Query(..., pattern="^(markdown|mermaid|json|pdf)$"),
    db: Session = Depends(get_db),
):
    playbook = _get_playbook_or_404(db, playbook_id)
    graph = _deserialize_graph(playbook.graph_json)

    if format == "pdf":
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="PDF export coming soon")

    if format == "markdown":
        if not graph:
            content = playbook.content_markdown or ""
        else:
            content = _to_markdown_from_graph(graph)
        return PlainTextResponse(
            content=content,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="playbook-{playbook_id}.md"'},
        )

    if format == "mermaid":
        return PlainTextResponse(
            content=_to_mermaid(graph or {"nodes": [], "edges": []}),
            media_type="text/plain",
        )

    tags = [{"id": tag.id, "name": tag.name} for tag in playbook.tags]
    payload = PlaybookExport(
        id=playbook.id,
        title=playbook.title,
        description=playbook.description,
        category=playbook.category,
        content_markdown=playbook.content_markdown,
        graph_json=graph,
        tags=tags,
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
        share_token=playbook.share_token,
        export_metadata={
            "exported_at": datetime.now(timezone.utc),
            "format_version": "1.0",
            "generator": "Playbook Forge",
        },
    )

    return JSONResponse(
        content=payload.model_dump(mode="json"),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="playbook-{playbook_id}.json"'},
    )


@router.post("/playbooks/import", response_model=PlaybookDetail, status_code=status.HTTP_201_CREATED)
def import_playbook(payload: PlaybookExport, db: Session = Depends(get_db)):
    if not payload.title or not payload.title.strip():
        raise HTTPException(status_code=400, detail="title is required")
    if not payload.category or not str(payload.category).strip():
        raise HTTPException(status_code=400, detail="category is required")

    playbook = Playbook(
        title=payload.title.strip(),
        description=payload.description,
        category=payload.category,
        content_markdown=payload.content_markdown,
        graph_json=_serialize_graph(payload.graph_json),
    )

    if payload.tags:
        playbook.tags = [_get_or_create_tag(db, tag.name if hasattr(tag, "name") else str(tag)) for tag in payload.tags]

    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    return _build_detail(playbook)


@router.post("/playbooks/import/bulk", response_model=List[BulkImportResult])
async def bulk_import_markdown(files: List[UploadFile] = File(...), db: Session = Depends(get_db)):
    results: List[BulkImportResult] = []

    for file in files:
        try:
            if not file.filename.lower().endswith(".md"):
                raise ValueError("Only .md files are supported")

            raw = await file.read()
            text = raw.decode("utf-8")

            title = "Imported Playbook"
            for line in text.splitlines():
                if line.strip().startswith("# "):
                    title = line.strip()[2:].strip() or title
                    break

            playbook = Playbook(
                title=title,
                description=None,
                category="Imported",
                content_markdown=text,
                graph_json=json.dumps({"nodes": [], "edges": []}),
            )
            db.add(playbook)
            db.commit()
            db.refresh(playbook)

            results.append(
                BulkImportResult(
                    filename=file.filename,
                    status="success",
                    playbook_id=playbook.id,
                )
            )
        except Exception as exc:
            db.rollback()
            results.append(
                BulkImportResult(
                    filename=file.filename,
                    status="error",
                    error=str(exc),
                )
            )

    return results
