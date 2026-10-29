"""Bounded, synthetic multipart uploads at the real ASGI/HTTP boundary."""
import asyncio
import hashlib
import json

import pytest

from api.tests.test_execution_hardening import _create_execution

LIMIT = 128 * 1024
OVERHEAD = 64 * 1024


@pytest.fixture
def upload(client, temp_db, api_key, monkeypatch, tmp_path):
    from api.routers import executions
    monkeypatch.setattr(executions, 'MAX_EVIDENCE_BYTES', LIMIT)
    # The helper does not exist on the vulnerable baseline.
    try:
        from api import evidence_upload
        monkeypatch.setattr(evidence_upload, 'MAX_EVIDENCE_BYTES', LIMIT)
    except ImportError:
        pass
    root = tmp_path / 'evidence'
    monkeypatch.setattr(executions, 'EVIDENCE_ROOT', root)
    rid = _create_execution(temp_db)
    return f'/api/executions/{rid}/steps/node_1/evidence', {'X-API-Key': api_key}, root, rid


def multipart(payload, extra=b''):
    return (b'--synthetic\r\nContent-Disposition: form-data; name="file"; filename="synthetic.bin"\r\n'
            b'Content-Type: application/octet-stream\r\n\r\n' + payload + b'\r\n' + extra + b'--synthetic--\r\n')


def streamed_request(client, url, headers, body, *, chunk_size=4096):
    """Feed distinct ASGI receive messages, without TestClient coalescing the stream."""
    messages = []
    read = 0

    async def receive():
        nonlocal read
        chunk = body[read:read + chunk_size]
        read += len(chunk)
        return {'type': 'http.request', 'body': chunk, 'more_body': read < len(body)}

    async def send(message):
        messages.append(message)

    scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1',
             'method': 'POST', 'scheme': 'http', 'path': url, 'raw_path': url.encode(),
             'query_string': b'', 'root_path': '', 'server': ('testserver', 80),
             'client': ('testclient', 123), 'headers': [(k.lower().encode(), v.encode()) for k, v in headers.items()]}
    asyncio.run(client.app(scope, receive, send))
    status = next(m['status'] for m in messages if m['type'] == 'http.response.start')
    return status, read


def assert_unmodified(client, upload, temp_db):
    from api.orm_models import Execution, ExecutionEvent, RunEvent
    url, headers, root, rid = upload
    assert not root.exists()
    with temp_db() as db:
        assert json.loads(db.get(Execution, rid).steps_json)[0]['evidence'] == []
        assert db.query(RunEvent).count() == 0
        assert db.query(ExecutionEvent).filter_by(event_type='evidence_attached').count() == 0


@pytest.mark.parametrize('payload', [b'\x00\xff' * (LIMIT // 2), ('é' * (LIMIT // 2)).encode()], ids=['binary', 'utf8'])
@pytest.mark.parametrize('length', [True, False])
def test_exact_file_budget_allows_multipart_overhead(client, upload, payload, length):
    url, headers, root, rid = upload
    body = multipart(payload)
    headers = {**headers, 'Content-Type': 'multipart/form-data; boundary=synthetic'}
    if length:
        headers['Content-Length'] = str(len(body))
    status, consumed = streamed_request(client, url, headers, body)
    assert status == 200
    assert consumed == len(body)
    assert (root / str(rid) / 'node_1' / 'synthetic.bin').read_bytes() == payload
    detail = client.get(f'/api/executions/{rid}', headers=headers).json()
    entry = detail['steps'][0]['evidence'][0]
    assert entry['size'] == LIMIT
    assert entry['sha256'] == hashlib.sha256(payload).hexdigest()


def test_file_budget_plus_one_has_no_storage_mutation(client, upload, temp_db, monkeypatch):
    url, headers, *_ = upload
    from starlette.datastructures import UploadFile
    original = UploadFile.read
    sizes = []
    async def read(file, size=-1):
        sizes.append(size)
        return await original(file, size)
    monkeypatch.setattr(UploadFile, 'read', read)
    response = client.post(url, headers=headers, files={'file': ('too-big.bin', b'x' * (LIMIT + 1))})
    assert response.status_code == 413
    assert sizes and all(0 < size <= 64 * 1024 for size in sizes)
    assert sum(sizes) == LIMIT + 1
    assert_unmodified(client, upload, temp_db)


@pytest.mark.parametrize('length', [None, '1', 'oversize'])
def test_ingress_budget_stops_stream_and_closes_spooled_files(client, upload, temp_db, monkeypatch, length):
    url, headers, *_ = upload
    opened = []
    from starlette import formparsers
    original = formparsers.SpooledTemporaryFile
    def spool(*args, **kwargs):
        file = original(*args, **kwargs)
        opened.append(file)
        return file
    monkeypatch.setattr(formparsers, 'SpooledTemporaryFile', spool)
    # Small first file, then a second large part: handler-only limits miss this.
    extra = b'--synthetic\r\nContent-Disposition: form-data; name="ignored"; filename="extra.bin"\r\n\r\n'
    body = multipart(b'normal', extra + b'x' * (LIMIT + OVERHEAD + 32768) + b'\r\n')
    headers = {**headers, 'Content-Type': 'multipart/form-data; boundary=synthetic'}
    if length is not None:
        headers['Content-Length'] = str(len(body)) if length == 'oversize' else length
    status, consumed = streamed_request(client, url, headers, body)
    assert status == 413
    assert consumed <= LIMIT + OVERHEAD + 4096
    assert consumed < len(body)
    assert all(file.closed for file in opened)
    if length == 'oversize':
        assert consumed == 0
        assert not opened
    assert_unmodified(client, upload, temp_db)


@pytest.mark.parametrize('key,expected', [(None, 401), ('wrong', 401), ('read-only', 403)])
def test_upload_auth_before_multipart_spooling(client, upload, monkeypatch, key, expected):
    url, headers, *_ = upload
    monkeypatch.setenv('HOTWASH_READ_ONLY_API_KEY', 'read-only')
    headers = {'Content-Type': 'multipart/form-data; boundary=synthetic'}
    if key is not None:
        headers['X-API-Key'] = key
    status, consumed = streamed_request(client, url, headers, multipart(b'x'))
    assert status == expected
    assert consumed == 0


@pytest.mark.parametrize('length', ['-1', 'nope', '1,2'])
def test_invalid_content_length_rejected_before_read(client, upload, temp_db, length):
    url, headers, *_ = upload
    status, consumed = streamed_request(client, url, {**headers, 'Content-Length': length,
        'Content-Type': 'multipart/form-data; boundary=synthetic'}, multipart(b'x'))
    assert status == 400
    assert consumed == 0
    assert_unmodified(client, upload, temp_db)


@pytest.mark.parametrize('extra_byte', [False, True])
def test_total_request_boundary(client, upload, temp_db, extra_byte):
    url, headers, *_ = upload
    extra = b'--synthetic\r\nContent-Disposition: form-data; name="ignored"; filename="extra.bin"\r\n\r\n'
    framing = multipart(b'normal', extra + b'\r\n')
    body = multipart(b'normal', extra + b'x' * (LIMIT + OVERHEAD - len(framing) + extra_byte) + b'\r\n')
    assert len(body) == LIMIT + OVERHEAD + extra_byte
    status, _ = streamed_request(client, url, {**headers, 'Content-Type': 'multipart/form-data; boundary=synthetic'}, body)
    assert status == (413 if extra_byte else 200)
    if extra_byte:
        assert_unmodified(client, upload, temp_db)
