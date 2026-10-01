"""Contract and real API regression evidence for evidence-record v1."""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / 'fixtures' / 'evidence-record'
SCHEMA = json.loads((ROOT / 'docs/schemas/evidence-record-v1.schema.json').read_text())
FORMATS = FormatChecker()


@FORMATS.checks('date-time', raises=(ValueError, OverflowError))
def rfc3339(value):
    # jsonschema's optional RFC3339 extra is not a runtime dependency here.
    # Register a real checker so invalid calendar dates cannot silently pass.
    if not isinstance(value, str):
        return True
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}[Tt](?:[01]\d|2[0-3]):[0-5]\d:(?:[0-5]\d|60)(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)', value):
        return False
    normalized = value.upper()
    # RFC3339 permits leap seconds. Calendar and offset validation still apply.
    leap = normalized[17:19] == '60'
    if leap:
        normalized = normalized[:17] + '59' + normalized[19:]
    parsed = datetime.fromisoformat(normalized.replace('Z', '+00:00')).astimezone(timezone.utc)
    return not leap or ((parsed.hour, parsed.minute, parsed.second) == (23, 59, 59)
                        and (parsed.month, parsed.day) in {(6, 30), (12, 31)})


VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FORMATS)


def validate(document):
    VALIDATOR.validate(document)
    return document


def test_schema_example_matches_documentation():
    Draft202012Validator.check_schema(SCHEMA)
    example = json.loads((FIXTURES / 'example.json').read_text())
    validate(example)
    documented = (ROOT / 'docs/evidence-record-v1.md').read_text().split('```json\n')[1].split('```')[0]
    assert json.loads(documented) == example
    extended = copy.deepcopy(example)
    extended['future'] = {'values': [1, None, 'opaque']}
    extended['records'][0]['source']['future'] = True
    validate(extended)


@pytest.mark.parametrize('mutation', json.loads((FIXTURES / 'invalid.json').read_text()), ids=lambda m: m['name'])
def test_schema_rejects_invalid_documents(mutation):
    document = json.loads((FIXTURES / 'example.json').read_text())
    parent = document
    for key in mutation['path'][:-1]:
        parent = parent[key]
    if mutation['delete']:
        del parent[mutation['path'][-1]]
    else:
        parent[mutation['path'][-1]] = mutation['value']
    with pytest.raises(ValidationError):
        validate(document)


@pytest.fixture
def run(client, temp_db, api_key, monkeypatch, tmp_path):
    from api.orm_models import Playbook
    from api.routers import executions
    monkeypatch.setattr(executions, 'EVIDENCE_ROOT', tmp_path / 'evidence')
    with temp_db() as db:
        playbook = Playbook(title='Evidence playbook', graph_json=json.dumps({'nodes': [
            {'id': 'collect', 'label': 'Collect evidence', 'type': 'step'},
            {'id': 'decide', 'label': 'Contain host?', 'type': 'decision'},
            {'id': 'same', 'label': 'Contain host?', 'type': 'decision'},
        ], 'edges': []}))
        db.add(playbook)
        db.commit()
        pid = playbook.id
    headers = {'X-API-Key': api_key}
    response = client.post('/api/executions', headers=headers, json={
        'playbook_id': pid, 'incident_title': 'Suspicious host', 'incident_id': 'INC-42', 'started_by': 'starter'})
    assert response.status_code == 201
    return response.json()['id'], headers, tmp_path


def export(client, run):
    rid, headers, _ = run
    response = client.get(f'/api/executions/{rid}/export?format=evidence-record', headers=headers)
    assert response.status_code == 200, response.text
    return validate(response.json())


def save_receipt_fixture(document, name):
    # Optional artifact output is confined to this worktree and used by the worker
    # to deliver actual API exporter responses, not hand-authored examples.
    import os
    if os.environ.get('HOTWASH_WRITE_EXPORT_FIXTURES') == '1':
        target = ROOT / '.brigade' / 'evidence-record-fixtures'
        target.mkdir(parents=True, exist_ok=True)
        (target / name).write_text(json.dumps(document, indent=2) + '\n')


def test_manual_export_provenance_decisions_and_legacy_reports(client, run, temp_db):
    from api.orm_models import RunEvent
    rid, headers, _ = run
    data = {'source_tool': 'zeek', 'source_ref': 'https://example.invalid/opaque', 'observed_at': '2026-09-29T10:12:13+02:00'}
    uploaded = client.post(f'/api/executions/{rid}/steps/collect/evidence', headers=headers,
                           data=data, files={'file': ('ioc.txt', b'example bytes', 'text/plain')})
    assert uploaded.status_code == 200
    evidence = uploaded.json()['evidence'][0]
    assert {key: evidence[key] for key in data} == data
    assert evidence['sha256'] == hashlib.sha256(b'example bytes').hexdigest()
    updated = client.patch(f'/api/executions/{rid}/steps/decide', headers=headers,
                          json={'decision_taken': 'Yes', 'assignee': 'assignee'})
    assert updated.status_code == 200
    with temp_db() as db:
        event = db.query(RunEvent).filter_by(execution_id=rid, event_type='step_decision_taken').one()
        payload = json.loads(event.payload_json)
        payload['actor'] = 'event-analyst'
        event.payload_json = json.dumps(payload)
        event.created_at = datetime(2026, 9, 29, 12, 34, 56)
        db.commit()
    # A later decision on another node must not supply this node's attribution.
    assert client.patch(f'/api/executions/{rid}/steps/same', headers=headers,
                        json={'decision_taken': 'Yes'}).status_code == 200
    client.patch(f'/api/executions/{rid}', headers=headers, json={'status': 'completed'})
    before = client.get(f'/api/executions/{rid}/report', headers=headers).json()
    markdown = client.get(f'/api/executions/{rid}/report/markdown', headers=headers).text
    document = export(client, run)
    assert document['subject'] == {'kind': 'run', 'id': str(rid), 'title': 'Suspicious host', 'incident_id': 'INC-42'}
    assert document['closeout'] == {'status': 'closed', 'resolution': None, 'impact': None, 'summary': None, 'closed_at': None, 'closed_by': None}
    source = document['records'][0]['source']
    assert source['tool'] == 'zeek'
    assert source['ref'] == 'sha256:' + evidence['sha256']
    assert source['observed_at'] == data['observed_at']
    assert source['raw']['source_ref'] == data['source_ref']
    decision = next(r for r in document['records'] if r['id'] == 'decision:decide')['decision']
    assert decision == {'verdict': 'unknown', 'rationale': 'Yes', 'by': 'event-analyst', 'at': '2026-09-29T12:34:56+00:00'}
    assert client.get(f'/api/executions/{rid}/report', headers=headers).json() == before
    assert client.get(f'/api/executions/{rid}/report/markdown', headers=headers).text == markdown
    assert set(before) == {'execution', 'playbook_title', 'metrics', 'timeline', 'steps'}
    assert markdown.startswith('# After-Action Report\n')
    assert client.get(f'/api/executions/{rid}/replay', headers=headers).json()['matches_persisted']
    save_receipt_fixture(document, 'manual-export.json')


def test_wazuh_ingested_export_uses_stored_fingerprint(client, run, temp_db):
    from api.orm_models import Execution, WazuhMapping
    from api.schemas import WazuhAlertIngest
    from api.services.ingest import process_alert
    rid, headers, _ = run
    alert = {'id': 'alert-42', 'timestamp': '2026-09-29T09:10:11Z',
             'rule': {'id': '5710', 'level': 8, 'description': 'Failed login', 'groups': ['authentication'], 'api_key': 'do-not-export'},
             'agent': {'id': '001', 'name': 'example-agent', 'ip': '192.0.2.42'},
             'full_log': 'do-not-export', 'data': {'password': 'do-not-export'}, 'api_key': 'do-not-export'}
    with temp_db() as db:
        original = db.get(Execution, rid)
        mapping = WazuhMapping(name='Example mapping', playbook_id=original.playbook_id, mode='auto', cooldown_seconds=0)
        db.add(mapping)
        db.flush()
        outcome = process_alert(db, mapping, WazuhAlertIngest(**alert), alert)
        eid = outcome['execution_id']
        stored = json.loads(db.get(Execution, eid).context_json)['ingest']['fingerprint']
    document = export(client, (eid, headers, run[2]))
    record = next(r for r in document['records'] if r['id'] == 'wazuh-alert')
    assert record['source']['tool'] == 'wazuh'
    assert record['source']['ref'] == stored
    assert record['source']['observed_at'] == '2026-09-29T09:10:11+00:00'
    assert record['source']['raw']['rule']['id'] == '5710'
    assert 'do-not-export' not in json.dumps(document)
    assert document['closeout']['status'] == 'open'
    save_receipt_fixture(document, 'wazuh-export.json')


def test_abandoned_export(client, run):
    rid, headers, _ = run
    assert client.patch(f'/api/executions/{rid}', headers=headers, json={'status': 'abandoned'}).status_code == 200
    document = export(client, run)
    assert document['records'] == []
    assert document['closeout']['status'] == 'closed'
    assert document['closeout']['resolution'] == 'Other'
    assert all(document['closeout'][key] is None for key in ('impact', 'summary', 'closed_at', 'closed_by'))


def test_historical_evidence_safe_hash_and_missing_provenance(client, run, temp_db):
    from api.orm_models import Execution
    rid, _, tmp = run
    target = tmp / 'evidence' / str(rid) / 'collect'
    target.mkdir(parents=True)
    (target / 'old.txt').write_bytes(b'old bytes')
    outside = tmp / 'outside.txt'
    outside.write_bytes(b'private bytes')
    (target / 'link.txt').symlink_to(outside)
    with temp_db() as db:
        execution = db.get(Execution, rid)
        steps = json.loads(execution.steps_json)
        steps[0]['evidence'] = [
            {'filename': name, 'size': 9, 'uploaded_at': '2026-09-29T09:10:11Z',
             'connector': 'thehive', 'result': {'api_key': 'do-not-export'}, 'path': str(outside)}
            for name in ('old.txt', 'missing.txt', '../outside.txt', 'link.txt')]
        execution.steps_json = json.dumps(steps)
        db.commit()
    document = export(client, run)
    assert document['records'][0]['source']['ref'] == 'sha256:' + hashlib.sha256(b'old bytes').hexdigest()
    assert all(r['source']['ref'] is None for r in document['records'][1:])
    assert all(r['source']['tool'] == 'thehive' for r in document['records'])
    assert 'private bytes' not in json.dumps(document)
    assert 'do-not-export' not in json.dumps(document)
    assert str(outside) not in json.dumps(document)


@pytest.mark.parametrize('field,value', [('observed_at', '2026-09-29'), ('observed_at', '2026-09-29T12:00:00'),
                                        ('observed_at', '2026-02-30T12:00:00Z'),
                                        ('observed_at', '2026-09-29T12:00:00+00:99'),
                                        ('observed_at', '2026-09-29T12:00:00+24:00'),
                                        ('observed_at', '2026-09-29T12:00:60Z'),
                                        ('observed_at', '2026-06-30T22:59:60Z'), ('source_tool', ''), ('source_ref', 'x'*1025)])
def test_invalid_provenance_rejected_before_file_write(client, run, field, value):
    rid, headers, tmp = run
    response = client.post(f'/api/executions/{rid}/steps/collect/evidence', headers=headers,
                           data={field: value}, files={'file': ('bad.txt', b'bytes', 'text/plain')})
    assert response.status_code == 422
    assert not (tmp / 'evidence').exists()


def test_export_missing_run_format_and_auth(client, run):
    rid, headers, _ = run
    assert client.get(f'/api/executions/{rid}/export').status_code == 401
    assert client.get('/api/executions/999999/export', headers=headers).status_code == 404
    assert client.get(f'/api/executions/{rid}/export?format=other', headers=headers).status_code == 422


def test_ambiguous_legacy_decision_never_invents_actor(client, run, temp_db):
    from api.orm_models import Execution, ExecutionEvent
    rid, _, _ = run
    with temp_db() as db:
        execution = db.get(Execution, rid)
        steps = json.loads(execution.steps_json)
        for step in steps[1:]:
            step.update(decision_taken='Yes', assignee='invented', completed_at='2026-09-29T12:00:00Z')
        execution.steps_json = json.dumps(steps)
        db.add(ExecutionEvent(execution_id=rid, event_type='decision_taken', actor='ambiguous', description="Decision 'Yes' on 'Contain host?'"))
        db.commit()
    decisions = [r['decision'] for r in export(client, run)['records']]
    assert all(d['by'] is None and d['at'] is None for d in decisions)


@pytest.mark.parametrize('timestamp', ['2026-09-29T12:00:00+23:59', '2016-12-31T23:59:60Z', '2017-01-01T00:59:60+01:00'])
def test_valid_rfc3339_provenance(client, run, timestamp):
    rid, headers, _ = run
    response = client.post(f'/api/executions/{rid}/steps/collect/evidence', headers=headers,
                           data={'observed_at': timestamp}, files={'file': ('valid.txt', b'bytes')})
    assert response.status_code == 200, response.text
    record = export(client, run)['records'][0]
    assert record['source']['observed_at'] is not None


def test_unique_legacy_decision_uses_matching_event(client, run, temp_db):
    from api.orm_models import Execution, ExecutionEvent
    rid, _, _ = run
    with temp_db() as db:
        execution = db.get(Execution, rid)
        steps = json.loads(execution.steps_json)
        steps[1]['decision_taken'] = 'suspicious'
        steps[2]['node_label'] = 'Different decision'
        execution.steps_json = json.dumps(steps)
        db.add(ExecutionEvent(execution_id=rid, event_type='decision_taken', actor='legacy-analyst',
                             timestamp=datetime(2026, 9, 29, 13, 0),
                             description="Decision 'suspicious' on 'Contain host?'"))
        db.commit()
    decision = export(client, run)['records'][0]['decision']
    assert decision == {'verdict': 'suspicious', 'rationale': 'suspicious', 'by': 'legacy-analyst', 'at': '2026-09-29T13:00:00+00:00'}


def test_fork_does_not_invent_decision_time(client, run):
    rid, headers, _ = run
    assert client.patch(f'/api/executions/{rid}/steps/decide', headers=headers, json={'decision_taken': 'No'}).status_code == 200
    fork = client.post(f'/api/executions/{rid}/fork', headers=headers)
    assert fork.status_code == 201
    document = export(client, (fork.json()['id'], headers, run[2]))
    assert document['records'][0]['decision']['by'] is None
    assert document['records'][0]['decision']['at'] is None


def test_wazuh_bounds_and_invalid_time_are_honest(client, run, temp_db):
    from api.orm_models import Execution
    rid, _, _ = run
    with temp_db() as db:
        execution = db.get(Execution, rid)
        execution.context_json = json.dumps({'wazuh_alert': {'timestamp': '2026-09-29T12:00:00+00:99',
                                                          'rule': {'groups': ['x']*65}}, 'ingest': {}})
        db.commit()
    source = export(client, run)['records'][0]['source']
    assert source['raw'] is None
    assert source['observed_at'] is None
    assert source['ref'] is None


def test_export_rejects_oversized_decision_without_truncation(client, run, temp_db):
    from api.orm_models import Execution
    rid, headers, _ = run
    with temp_db() as db:
        execution = db.get(Execution, rid)
        steps = json.loads(execution.steps_json)
        steps[1]['decision_taken'] = 'x'*8193
        execution.steps_json = json.dumps(steps)
        db.commit()
    response = client.get(f'/api/executions/{rid}/export', headers=headers)
    assert response.status_code == 422
    assert response.json()['detail'] == 'Decision text exceeds evidence-record v1 bounds'


@pytest.mark.parametrize('field,value', [('steps_json', '{'), ('steps_json', '{}'), ('steps_json', 'null'),
                                        ('context_json', '{'), ('context_json', '[]'), ('context_json', 'null'),
                                        ('context_json', '{"invalid": NaN}')])
def test_corrupted_persisted_input_fails_export_preserving_legacy(client, run, temp_db, field, value):
    from api.orm_models import Execution
    rid, headers, _ = run
    with temp_db() as db:
        execution = db.get(Execution, rid)
        setattr(execution, field, value)
        db.commit()
    response = client.get(f'/api/executions/{rid}/export', headers=headers)
    assert response.status_code == 422
    assert response.json()['detail'] == f'Invalid stored {field} for evidence export'
    legacy = client.get(f'/api/executions/{rid}/report', headers=headers)
    assert legacy.status_code == 200
    if field == 'steps_json':
        assert legacy.json()['steps'] == []
    assert client.get(f'/api/executions/{rid}/report/markdown', headers=headers).status_code == 200


def test_malformed_nested_evidence_fails_export(client, run, temp_db):
    from api.orm_models import Execution
    rid, headers, _ = run
    with temp_db() as db:
        execution = db.get(Execution, rid)
        steps = json.loads(execution.steps_json)
        steps[0]['evidence'] = {}
        execution.steps_json = json.dumps(steps)
        db.commit()
    response = client.get(f'/api/executions/{rid}/export', headers=headers)
    assert response.status_code == 422
    assert response.json()['detail'] == 'Invalid historical evidence collection'


def _store_steps(temp_db, rid, steps, context=None):
    from api.orm_models import Execution
    with temp_db() as db:
        execution = db.get(Execution, rid)
        execution.steps_json = json.dumps(steps)
        execution.context_json = context
        db.commit()


@pytest.mark.parametrize('count,status', [(10000, 200), (10001, 422)])
def test_record_count_boundary_is_explicit(client, run, temp_db, count, status):
    rid, headers, _ = run
    _store_steps(temp_db, rid, [{'node_id': 'collect', 'evidence': [{} for _ in range(count)]}])
    response = client.get(f'/api/executions/{rid}/export', headers=headers)
    assert response.status_code == status, response.text[:500]
    if status == 200:
        assert len(response.json()['records']) == count
        assert response.json()['records'][-1]['id'] == 'evidence:collect:9999'
    else:
        assert response.json()['detail'] == 'Evidence record count exceeds v1 bounds'


@pytest.mark.parametrize('extra,status', [(0, 200), (1, 422)])
def test_stored_input_byte_boundary_is_explicit(client, run, temp_db, extra, status):
    rid, headers, _ = run
    byte_limit = 4 * 1024 * 1024
    steps = '[]'
    empty_context = json.dumps({'ignored_provider_payload': ''})
    context = json.dumps({'ignored_provider_payload': 'x'*(byte_limit-len(steps)-len(empty_context)+extra)})
    assert len(steps.encode()) + len(context.encode()) == byte_limit + extra
    _store_steps(temp_db, rid, [], context)
    response = client.get(f'/api/executions/{rid}/export', headers=headers)
    assert response.status_code == status, response.text[:500]
    if status == 200:
        assert response.json()['records'] == []
        assert 'ignored_provider_payload' not in response.text
    else:
        assert response.json()['detail'] == 'Stored execution input exceeds 4 MiB export limit'


def test_output_byte_limit_is_explicit_with_input_under_limit(client, run, temp_db):
    rid, headers, _ = run
    # Original rationale is retained both in decision and source facts. This
    # produces >4 MiB of output while stored input remains <4 MiB.
    steps = [{'node_id': f'node_{i}', 'node_label': f'Decision {i}', 'decision_taken': 'x'*8192}
             for i in range(270)]
    assert len(json.dumps(steps).encode()) < 4 * 1024 * 1024
    _store_steps(temp_db, rid, steps)
    response = client.get(f'/api/executions/{rid}/export', headers=headers)
    assert response.status_code == 422
    assert response.json()['detail'] == 'Evidence record exceeds 4 MiB export limit'


def _projection(steps, tmp_path, *, run_events=(), events=(), max_file_bytes=1024):
    from types import SimpleNamespace
    from api.services.evidence_record import build_evidence_record
    execution = SimpleNamespace(id=42, steps_json=json.dumps(steps), context_json=None,
                                run_events=run_events, events=events, incident_title='Historical run',
                                incident_id=None, status='running')
    return build_evidence_record(execution, evidence_root=tmp_path, max_file_bytes=max_file_bytes,
                                 generator_version=None)


@pytest.mark.parametrize('exists', [True, False])
def test_export_hashes_repeated_file_only_once_per_export(tmp_path, monkeypatch, exists):
    from api.services import evidence_record as service
    target = tmp_path / '42' / 'collect'
    target.mkdir(parents=True)
    if exists:
        (target / 'old.txt').write_bytes(b'old bytes')
    original = service._file_hash
    calls = []

    def counted(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(service, '_file_hash', counted)
    steps = [{'node_id': 'collect', 'evidence': [{'filename': 'old.txt'} for _ in range(1000)]}]
    expected = 'sha256:' + hashlib.sha256(b'old bytes').hexdigest() if exists else None
    for _ in range(2):
        document = _projection(steps, tmp_path)
        assert all(record['source']['ref'] == expected for record in document['records'])
    # Cache failures as well as hashes, but never carry a cache into another export.
    assert len(calls) == 2


def test_export_shares_hash_read_budget_across_files(tmp_path, monkeypatch):
    from api.services import evidence_record as service
    target = tmp_path / '42' / 'collect'
    target.mkdir(parents=True)
    for name in ('a', 'b', 'c'):
        (target / name).write_bytes(b'123456')
    original = service.os.read
    read_bytes = []

    def counted(fd, size):
        chunk = original(fd, size)
        read_bytes.append(len(chunk))
        return chunk

    monkeypatch.setattr(service.os, 'read', counted)
    document = _projection([{'node_id': 'collect', 'evidence': [{'filename': name} for name in ('a', 'b', 'c')]}],
                           tmp_path, max_file_bytes=10)
    assert sum(read_bytes) <= 10
    assert document['records'][0]['source']['ref'] == 'sha256:' + hashlib.sha256(b'123456').hexdigest()
    assert all(record['source']['ref'] is None for record in document['records'][1:])


@pytest.mark.parametrize('failure', ['read_error', 'growth'])
def test_export_hash_budget_counts_failed_and_growing_reads(tmp_path, monkeypatch, failure):
    from api.services import evidence_record as service
    target = tmp_path / '42' / 'collect'
    target.mkdir(parents=True)
    (target / 'a').write_bytes(b'123456')
    (target / 'b').write_bytes(b'abcdef')
    original = service.os.read
    read_bytes = []
    calls = 0

    def changed_read(fd, size):
        nonlocal calls
        calls += 1
        if calls == 2 and failure == 'read_error':
            raise OSError('simulated read failure after partial consumption')
        chunk = original(fd, min(size, 3) if calls == 1 else size)
        read_bytes.append(len(chunk))
        if calls == 1 and failure == 'growth':
            with (target / 'a').open('ab') as stream:
                stream.write(b'grew beyond the export budget')
        return chunk

    monkeypatch.setattr(service.os, 'read', changed_read)
    document = _projection([{'node_id': 'collect', 'evidence': [{'filename': 'a'}, {'filename': 'b'}]}],
                           tmp_path, max_file_bytes=8)
    assert sum(read_bytes) <= 8
    assert all(record['source']['ref'] is None for record in document['records'])


def test_export_hashes_file_at_exact_budget(tmp_path, monkeypatch):
    from api.services import evidence_record as service
    target = tmp_path / '42' / 'collect'
    target.mkdir(parents=True)
    (target / 'a').write_bytes(b'12345678')
    (target / 'empty').write_bytes(b'')
    document = _projection([{'node_id': 'collect', 'evidence': [{'filename': 'a'}, {'filename': 'empty'}]}],
                           tmp_path, max_file_bytes=8)
    assert [r['source']['ref'] for r in document['records']] == [
        'sha256:' + hashlib.sha256(b'12345678').hexdigest(), 'sha256:' + hashlib.sha256(b'').hexdigest()]


class _CountedTraversal(list):
    visits = 0

    def __iter__(self):
        for value in super().__iter__():
            self.visits += 1
            yield value

    def __reversed__(self):
        for value in super().__reversed__():
            self.visits += 1
            yield value


@pytest.mark.parametrize('legacy', [False, True])
def test_export_indexes_decision_attribution_with_linear_traversal(tmp_path, monkeypatch, legacy):
    from types import SimpleNamespace
    from api.services import evidence_record as service
    count = 1000
    steps = [{'node_id': f'n{i}', 'node_label': f'Label {i}', 'decision_taken': 'Yes'} for i in range(count)]
    label_reads = []

    class CountedStep(dict):
        def get(self, key, *args):
            if key == 'node_label':
                label_reads.append(key)
            return super().get(key, *args)

    original = service._export_json

    def counted_steps(value, field, expected_type):
        result = original(value, field, expected_type)
        return [CountedStep(step) for step in result] if field == 'steps_json' else result

    monkeypatch.setattr(service, '_export_json', counted_steps)
    at = datetime(2026, 9, 29, 13, 0)
    run_events = _CountedTraversal(SimpleNamespace(
        id=i+1, event_type='step_decision_taken', created_at=at,
        payload_json=json.dumps({'node_id': f'other{i}' if legacy else f'n{i}', 'decision': 'Yes', 'actor': f'actor{i}'}))
        for i in range(count))
    events = _CountedTraversal(SimpleNamespace(id=i+1, event_type='decision_taken', actor=f'actor{i}', timestamp=at,
                                              description=f"Decision 'Yes' on 'Label {i}'") for i in range(count))
    document = _projection(steps, tmp_path, run_events=run_events, events=events)
    assert [r['decision']['by'] for r in document['records']] == [f'actor{i}' for i in range(count)]
    assert all(r['decision']['at'] == '2026-09-29T13:00:00+00:00' for r in document['records'])
    assert run_events.visits <= 2 * count
    assert events.visits <= 2 * count
    assert len(label_reads) <= 4 * count


def test_indexed_decisions_keep_latest_matching_text_and_fork_boundary(tmp_path):
    from types import SimpleNamespace
    from api.services.replay import RUN_FORKED, STEP_DECISION_TAKEN
    at = datetime(2026, 9, 29, 13, 0)

    def decision_event(event_id, node_id, text, actor):
        return SimpleNamespace(id=event_id, event_type=STEP_DECISION_TAKEN, created_at=at,
                               payload_json=json.dumps({'node_id': node_id, 'decision': text, 'actor': actor}))

    steps = [{'node_id': node, 'node_label': node, 'decision_taken': 'Yes'} for node in ('old', 'new', 'missing')]
    run_events = [decision_event(1, 'old', 'Yes', 'before-fork'),
                  SimpleNamespace(id=2, event_type=RUN_FORKED),
                  decision_event(3, 'new', 'Yes', 'old-match'),
                  decision_event(4, 'new', 'Yes', 'latest-match'),
                  decision_event(5, 'new', 'No', 'different-text')]
    legacy = [SimpleNamespace(id=9, event_type='decision_taken', actor='legacy', timestamp=at,
                              description=f"Decision 'Yes' on '{node}'") for node in ('old', 'missing')]
    decisions = [r['decision'] for r in _projection(steps, tmp_path, run_events=run_events, events=legacy)['records']]
    assert [d['by'] for d in decisions] == [None, 'latest-match', None]
    assert [d['at'] for d in decisions] == [None, '2026-09-29T13:00:00+00:00', None]


def test_indexed_legacy_decisions_use_latest_id_and_count_nondecision_labels(tmp_path):
    from types import SimpleNamespace
    at = datetime(2026, 9, 29, 13, 0)
    steps = [{'node_id': 'unique', 'node_label': 'Unique', 'decision_taken': 'Yes'},
             {'node_id': 'duplicate', 'node_label': 'Duplicate', 'decision_taken': 'Yes'},
             {'node_id': 'no-decision', 'node_label': 'Duplicate'}]
    events = [SimpleNamespace(id=event_id, event_type='decision_taken', actor=actor, timestamp=at,
                              description=f"Decision 'Yes' on '{label}'")
              for event_id, actor, label in ((10, 'latest-id', 'Unique'), (2, 'older-id', 'Unique'),
                                            (11, 'ambiguous', 'Duplicate'))]
    decisions = [r['decision'] for r in _projection(steps, tmp_path, events=events)['records']]
    assert [d['by'] for d in decisions] == ['latest-id', None]
