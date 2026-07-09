"""
Seed script for Hotwash database.

Reads markdown playbooks from the shared workspace and inserts them
when the database is empty.
"""

from __future__ import annotations

import json
import logging
import re
import secrets as secrets_module
from pathlib import Path
from typing import List, Optional, Set

from sqlalchemy.orm import Session

from api._compat import getenv_compat
from api.crypto import encrypt_secret
from api.database import SessionLocal, init_db
from api.orm_models import Playbook, WazuhMapping
from api.parsers.markdown_parser import MarkdownParser
from api.services.tags import get_or_create_tag, normalize_tag

logger = logging.getLogger(__name__)

PLAYBOOKS_DIR = Path("/home/user/.openclaw/workspace/playbooks")


def _parse_front_matter_tags(content: str) -> List[str]:
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return []

    tags: List[str] = []
    i = 1
    while i < len(lines):
        line = lines[i].strip()
        if line == "---":
            break
        if line.startswith("tags:"):
            remainder = line.split(":", 1)[1].strip()
            if remainder.startswith("[") and remainder.endswith("]"):
                inner = remainder[1:-1]
                tags.extend([item.strip() for item in inner.split(",") if item.strip()])
            else:
                j = i + 1
                while j < len(lines):
                    tag_line = lines[j].strip()
                    if not tag_line.startswith("-"):
                        break
                    tags.append(tag_line.lstrip("-").strip())
                    j += 1
                i = j - 1
        i += 1

    return tags


def _extract_title(content: str) -> Optional[str]:
    match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return None


def _extract_description(content: str) -> Optional[str]:
    lines = content.splitlines()
    found_title = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("---"):
            continue
        if stripped.startswith("#"):
            found_title = True
            continue
        if found_title and stripped and not stripped.startswith("**"):
            return stripped
    return None


def _extract_metadata_tags(content: str) -> List[str]:
    tags: List[str] = []
    type_match = re.search(r"^\*\*Type:\*\*\s*(.+)$", content, re.MULTILINE)
    tooling_match = re.search(r"^\*\*Tooling:\*\*\s*(.+)$", content, re.MULTILINE)

    for match in [type_match, tooling_match]:
        if not match:
            continue
        raw = match.group(1)
        for part in re.split(r"[+/,:]", raw):
            cleaned = part.strip()
            if cleaned:
                tags.append(cleaned)

    return tags


def _infer_category(path: Path) -> str:
    stem = path.stem.lower()
    if "vulnerability" in stem or "remediation" in stem:
        return "Vulnerability Remediation"
    if "incident" in stem:
        return "Incident Response"
    if "threat" in stem or "hunting" in stem:
        return "Threat Hunting"
    return "Custom"


def _parse_graph_json(content_markdown: str) -> str:
    parser = MarkdownParser()
    graph = parser.parse(content_markdown)
    return json.dumps(graph.model_dump())


def _collect_tags(content: str) -> Set[str]:
    tags: Set[str] = set()
    for tag in _parse_front_matter_tags(content):
        normalized = normalize_tag(tag)
        if normalized:
            tags.add(normalized)

    for tag in _extract_metadata_tags(content):
        normalized = normalize_tag(tag)
        if normalized:
            tags.add(normalized)

    return tags


def seed_integrations(db: Session) -> int:
    """Seed any missing default integrations."""
    from api.integrations.config import Integration, DEFAULT_INTEGRATIONS

    existing_tools = {
        row[0]
        for row in db.query(Integration.tool_name).all()
    }

    inserted = 0
    for item in DEFAULT_INTEGRATIONS:
        if item["tool_name"] in existing_tools:
            continue
        db.add(Integration(
            tool_name=item["tool_name"],
            display_name=item["display_name"],
            mock_mode=True,
            enabled=False,
            verify_ssl=True,
            last_status="unchecked",
        ))
        inserted += 1
    db.commit()
    return inserted


def seed(db: Session) -> int:
    """Seed the database if empty. Returns number of playbooks inserted."""
    existing_count = db.query(Playbook).count()
    if existing_count > 0:
        return 0

    if not PLAYBOOKS_DIR.exists():
        return 0

    inserted = 0
    for path in sorted(PLAYBOOKS_DIR.glob("*.md")):
        if path.name.upper().startswith("TEMPLATE"):
            continue

        content = path.read_text(encoding="utf-8")
        title = _extract_title(content) or path.stem.replace("-", " ").title()
        description = _extract_description(content)
        category = _infer_category(path)
        graph_json = _parse_graph_json(content)

        playbook = Playbook(
            title=title,
            description=description,
            category=category,
            content_markdown=content,
            graph_json=graph_json,
        )

        tags = _collect_tags(content)
        if tags:
            playbook.tags = [get_or_create_tag(db, tag) for tag in sorted(tags)]

        db.add(playbook)
        inserted += 1

    db.commit()
    return inserted


SEED_WAZUH_MAPPING_NAME = "Wazuh vulnerability-detector (seed)"
SEED_WAZUH_RULE_ID = "23505"
SEED_WAZUH_PLAYBOOK_TITLE = "Wazuh SOC Playbook: Before/After Vulnerability Export"


def seed_wazuh_mappings(db: Session) -> int:
    """Seed one default Wazuh mapping if none exist.

    Maps rule_id 23505 (vulnerability-detector level 10) to the seeded Wazuh
    SOC playbook in `suggest` mode with a 5-minute cooldown. The HMAC secret
    comes from HOTWASH_WAZUH_SEED_SECRET if set, otherwise a fresh urlsafe
    token is generated and logged once at WARNING level so it can be captured.
    """
    if db.query(WazuhMapping).count() > 0:
        return 0

    playbook = (
        db.query(Playbook)
        .filter(Playbook.title == SEED_WAZUH_PLAYBOOK_TITLE, Playbook.is_deleted.is_(False))
        .first()
    )
    if playbook is None:
        logger.info(
            "Skipping Wazuh mapping seed: playbook %r not present yet",
            SEED_WAZUH_PLAYBOOK_TITLE,
        )
        return 0

    secret = getenv_compat("HOTWASH_WAZUH_SEED_SECRET", "PLAYBOOK_FORGE_WAZUH_SEED_SECRET")
    if not secret:
        secret = secrets_module.token_urlsafe(32)
        logger.warning(
            "Generated ephemeral Wazuh ingest seed secret for mapping %r. "
            "Set HOTWASH_WAZUH_SEED_SECRET to make this deterministic across "
            "restarts; otherwise rotate via PATCH /api/ingest/mappings/{id}.",
            SEED_WAZUH_MAPPING_NAME,
        )
        # Never log the secret itself; rotate via the mappings API to obtain
        # a usable value when this ephemeral path was taken.

    encrypted = encrypt_secret(secret)
    if not encrypted:
        logger.error("Failed to encrypt Wazuh seed secret; skipping mapping seed")
        return 0

    mapping = WazuhMapping(
        name=SEED_WAZUH_MAPPING_NAME,
        playbook_id=playbook.id,
        mode="suggest",
        rule_id_pattern=SEED_WAZUH_RULE_ID,
        rule_groups_pattern=None,
        agent_name_pattern=None,
        cooldown_seconds=300,
        hmac_secret_encrypted=encrypted,
        enabled=True,
    )
    db.add(mapping)
    db.commit()
    return 1


def seed_db() -> int:
    """Convenience wrapper to seed with its own DB session."""
    db = SessionLocal()
    try:
        seed_integrations(db)
        inserted = seed(db)
        seed_wazuh_mappings(db)
        return inserted
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    count = seed_db()
    print(f"Seeded {count} playbooks.")
