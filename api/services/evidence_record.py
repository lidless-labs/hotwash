"""Bounded evidence-record v1 projection. No provider calls or ref fetching."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from api.orm_models import Execution
from api.services.replay import RUN_FORKED, STEP_DECISION_TAKEN

VERDICTS = {'benign', 'suspicious', 'malicious', 'false-positive', 'unknown'}
RFC3339 = re.compile(r'^\d{4}-\d{2}-\d{2}[Tt](?:[01]\d|2[0-3]):[0-5]\d:(?:[0-5]\d|60)(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$')
MAX_EXPORT_BYTES = 4 * 1024 * 1024
MAX_RAW_BYTES = 32 * 1024


def source_time(value: Any) -> str | None:
    """Unknown, invalid, and offset-free source dates stay unknown."""
    if not isinstance(value, str) or len(value) > 64 or not RFC3339.fullmatch(value):
        return None
    try:
        normalized = value.upper()
        leap_second = normalized[17:19] == '60'
        parsed_text = normalized[:17] + '59' + normalized[19:] if leap_second else normalized
        parsed = datetime.fromisoformat(parsed_text.replace('Z', '+00:00'))
        if leap_second:
            utc = parsed.astimezone(timezone.utc)
            if (utc.hour, utc.minute, utc.second) != (23, 59, 59) or (utc.month, utc.day) not in {(6, 30), (12, 31)}:
                return None
            return normalized
        return parsed.isoformat()
    except (ValueError, OverflowError):
        return None


def event_time(value: datetime | None) -> str | None:
    if value is None:
        return None
    # SQLite server_default timestamps are UTC even though DateTime is naive.
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


def _text(value: Any, limit: int = 1024, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError('Evidence record text exceeds v1 bounds or has invalid shape')
    return value


def _bounded_json(value: Any, depth: int = 4) -> bool:
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, str):
        return len(value) <= 8192
    if isinstance(value, (float, int)):
        return -1e308 <= value <= 1e308 and math.isfinite(value)
    if depth == 0:
        return False
    if isinstance(value, list):
        return len(value) <= 64 and all(_bounded_json(v, depth - 1) for v in value)
    if isinstance(value, dict):
        return len(value) <= 64 and all(isinstance(k, str) and len(k) <= 128 and _bounded_json(v, depth - 1) for k, v in value.items())
    return False


def _raw(value: dict) -> dict | None:
    if not _bounded_json(value):
        return None
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
    return value if len(encoded) <= MAX_RAW_BYTES else None


def _object_json(value: str | None) -> dict:
    try:
        parsed = json.loads(value) if value else {}
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _export_json(value: str | None, field: str, expected_type: type) -> Any:
    if value is None and field == 'context_json':
        return {}
    def reject_constant(constant: str) -> None:
        raise ValueError(f'Non-finite JSON number: {constant}')
    try:
        parsed = json.loads(value, parse_constant=reject_constant)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError(f'Invalid stored {field} for evidence export') from exc
    if not isinstance(parsed, expected_type):
        raise ValueError(f'Invalid stored {field} for evidence export')
    return parsed


@dataclass
class _HashBudget:
    remaining: int


def _file_hash(root: Path, execution_id: int, node_id: str, filename: str | None,
               max_bytes: int, budget: _HashBudget) -> str | None:
    """Open each reconstructed component relative to a held directory descriptor.

    O_NOFOLLOW on directories and file blocks traversal and symlink replacement
    races. Never inspect stored paths, upstream refs, or non-regular files.
    """
    if not isinstance(node_id, str) or node_id in {'.', '..'} or not re.fullmatch(r'[A-Za-z0-9._-]{1,128}', node_id):
        return None
    if (not isinstance(filename, str) or not filename or len(filename) > 255
            or filename in {'.', '..'} or '/' in filename or '\\' in filename
            or any(ord(c) < 32 for c in filename)):
        return None
    descriptors = []
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptors.append(os.open(root, flags))
        for component in (str(execution_id), node_id):
            descriptors.append(os.open(component, flags, dir_fd=descriptors[-1]))
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptors[-1])
        descriptors.append(fd)
        info = os.fstat(fd)
        limit = min(max_bytes, budget.remaining)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return None
        digest = hashlib.sha256()
        total = 0
        while total < limit:
            chunk = os.read(fd, min(65536, limit - total))
            if not chunk:
                return digest.hexdigest()
            # Consumption survives errors and rejected hashes. Never read a
            # probe byte beyond the shared budget, even if this file grows.
            budget.remaining -= len(chunk)
            total += len(chunk)
            digest.update(chunk)
        # At the exact boundary, inspect the held descriptor for growth rather
        # than spending another byte to distinguish EOF from an oversized file.
        return digest.hexdigest() if os.fstat(fd).st_size == total else None
    except (OSError, ValueError):
        return None
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _label_key(value: Any) -> Any:
    """Preserve equality for historical JSON labels, including lists/objects."""
    if isinstance(value, list):
        return (list, tuple(_label_key(item) for item in value))
    if isinstance(value, dict):
        return (dict, frozenset((key, _label_key(item)) for key, item in value.items()))
    return value


@dataclass
class _DecisionIndex:
    matching: dict[tuple[str, str], tuple[Any, dict]]
    last_fork: int
    legacy: dict[str, Any]
    label_counts: dict[Any, int]


def _decision_index(execution: Execution, steps: list[dict]) -> _DecisionIndex:
    index = _DecisionIndex({}, 0, {}, {})
    has_decisions = False
    for step in steps:
        if not isinstance(step, dict):
            raise ValueError('Invalid historical step shape')
        label = _label_key(step.get('node_label'))
        index.label_counts[label] = index.label_counts.get(label, 0) + 1
        has_decisions |= step.get('decision_taken') is not None
    if not has_decisions:
        return index
    # run_events is ordered by id. Keep the same last matching event as the
    # former reverse scan, without parsing or visiting it for every decision.
    for event in reversed(execution.run_events):
        if event.event_type == RUN_FORKED:
            index.last_fork = max(index.last_fork, event.id)
        elif event.event_type == STEP_DECISION_TAKEN:
            payload = _object_json(event.payload_json)
            node_id, text = payload.get('node_id'), payload.get('decision')
            if isinstance(node_id, str) and isinstance(text, str):
                index.matching.setdefault((node_id, text), (event, payload))
    if not index.last_fork:
        for event in execution.events:
            if event.event_type == 'decision_taken':
                previous = index.legacy.get(event.description)
                if previous is None or event.id > previous.id:
                    index.legacy[event.description] = event
    return index


def _decision(step: dict, index: _DecisionIndex) -> dict:
    text = step['decision_taken']
    if not isinstance(text, str) or len(text) > 8192:
        raise ValueError('Decision text exceeds evidence-record v1 bounds')
    actor = at = None
    matched = index.matching.get((step.get('node_id'), text))
    if matched is not None:
        event, payload = matched
        if event.id > index.last_fork:
            actor = _text(payload.get('actor'))
            at = event_time(event.created_at)
    elif not index.last_fork:
        label = step.get('node_label')
        if index.label_counts[_label_key(label)] == 1:
            event = index.legacy.get(f"Decision '{text}' on '{label}'")
            if event:
                actor, at = _text(event.actor), event_time(event.timestamp)
    return {'verdict': text if text in VERDICTS else 'unknown', 'rationale': text, 'by': actor, 'at': at}


def _record(record_id: str, tool: str, observed_at: str | None, ref: str | None, raw: dict, decision: dict | None = None) -> dict:
    return {'id': _text(record_id, required=True),
            'source': {'tool': _text(tool, required=True), 'observed_at': observed_at, 'ref': _text(ref), 'raw': _raw(raw)},
            'enrichment': [], 'decision': decision}


def build_evidence_record(execution: Execution, *, evidence_root: Path, max_file_bytes: int, generator_version: str | None) -> dict:
    stored_bytes = sum(len(value.encode('utf-8')) for value in (execution.steps_json, execution.context_json)
                       if isinstance(value, str))
    if stored_bytes > MAX_EXPORT_BYTES:
        raise ValueError('Stored execution input exceeds 4 MiB export limit')
    steps = _export_json(execution.steps_json, 'steps_json', list)
    context = _export_json(execution.context_json, 'context_json', dict)
    records = []
    # Bound all fallback hashing in one export to the configured per-file cap.
    # Stored valid digests do not require filesystem reads or consume budget.
    hash_budget = _HashBudget(max(0, max_file_bytes))
    file_hashes: dict[tuple[str, str | None], str | None] = {}
    decisions = _decision_index(execution, steps)
    for step in steps:
        if not isinstance(step, dict):
            raise ValueError('Invalid historical step shape')
        node_id = step.get('node_id')
        if not isinstance(step.get('node_id'), str) or not step['node_id'] or len(step['node_id']) > 1024:
            raise ValueError('Invalid historical step identity')
        evidence = step.get('evidence', [])
        if not isinstance(evidence, list):
            raise ValueError('Invalid historical evidence collection')
        for index, item in enumerate(evidence):
            if len(records) >= 10000:
                raise ValueError('Evidence record count exceeds v1 bounds')
            if not isinstance(item, dict):
                raise ValueError('Invalid historical evidence shape')
            digest = item.get('sha256')
            if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
                filename = item.get('filename')
                filename = filename if isinstance(filename, str) else None
                key = (node_id, filename)
                if key not in file_hashes:
                    file_hashes[key] = _file_hash(evidence_root, execution.id, node_id, filename,
                                                  max_file_bytes, hash_budget)
                digest = file_hashes[key]
            raw = {key: item.get(key) if isinstance(item.get(key), str) else None
                   for key in ('filename', 'uploaded_at', 'connector', 'action', 'source_tool', 'source_ref', 'observed_at')}
            raw['size'] = item.get('size') if type(item.get('size')) is int and item['size'] >= 0 else None
            raw.update(node_id=node_id, sha256=digest)
            records.append(_record(f'evidence:{node_id}:{index}', item.get('source_tool') or item.get('connector') or 'hotwash',
                                   source_time(item.get('observed_at')) or source_time(item.get('uploaded_at')),
                                   'sha256:' + digest if digest else None, raw))
        if step.get('decision_taken') is not None:
            decision = _decision(step, decisions)
            records.append(_record(f'decision:{node_id}', 'hotwash', decision['at'], None,
                                   {'node_id': node_id, 'decision_taken': step['decision_taken']}, decision))
        if len(records) > 10000:
            raise ValueError('Evidence record count exceeds v1 bounds')
    alert = context.get('wazuh_alert')
    if isinstance(alert, dict):
        raw = {key: alert[key] for key in ('id', 'timestamp') if key in alert and isinstance(alert[key], (str, int, float, bool, type(None)))}
        # Select source fields, never copy arbitrary nested provider data.
        for section, fields in (('rule', ('id', 'level', 'description', 'groups')), ('agent', ('id', 'name', 'ip'))):
            data = alert.get(section)
            if isinstance(data, dict):
                raw[section] = {key: data[key] for key in fields if key in data and
                                (isinstance(data[key], (str, int, float, bool, type(None))) or
                                 (key == 'groups' and isinstance(data[key], list) and all(isinstance(v, str) for v in data[key])))}
        ingest = context.get('ingest')
        fingerprint = ingest.get('fingerprint') if isinstance(ingest, dict) else None
        records.append(_record('wazuh-alert', 'wazuh', source_time(alert.get('timestamp')), fingerprint, raw))
    if len(records) > 10000:
        raise ValueError('Evidence record count exceeds v1 bounds')
    document = {'format': 'evidence-record', 'format_version': '1',
                'generator': {'name': 'hotwash', 'version': _text(generator_version)},
                'exported_at': datetime.now(timezone.utc).isoformat(),
                'subject': {'kind': 'run', 'id': str(execution.id), 'title': _text(execution.incident_title, required=True),
                            'incident_id': _text(execution.incident_id)},
                'records': records,
                'closeout': {'status': 'closed' if execution.status in {'completed', 'abandoned'} else 'open',
                             'resolution': 'Other' if execution.status == 'abandoned' else None,
                             'impact': None, 'summary': None, 'closed_at': None, 'closed_by': None}}
    if len(json.dumps(document, ensure_ascii=False, allow_nan=False).encode('utf-8')) > MAX_EXPORT_BYTES:
        raise ValueError('Evidence record exceeds 4 MiB export limit')
    return document
