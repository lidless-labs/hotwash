"""Bound the evidence route before FastAPI parses and spools multipart data."""
from fastapi import HTTPException, Request
from fastapi.routing import APIRoute
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.formparsers import MultiPartException

from api.auth import get_api_key

MAX_EVIDENCE_BYTES = 25 * 1024 * 1024
# Includes boundaries, headers, filename and optional UTF-8 provenance fields.
MAX_MULTIPART_OVERHEAD_BYTES = 64 * 1024


class EvidenceUploadRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def bounded_upload(request: Request):
            # FastAPI normally parses File/Form bodies before dependencies run.
            # Authenticate here as well, before any multipart data is spooled.
            get_api_key(request, request.headers.get('x-api-key'))
            budget = MAX_EVIDENCE_BYTES + MAX_MULTIPART_OVERHEAD_BYTES
            lengths = request.headers.getlist('content-length')
            if lengths:
                if (len(lengths) != 1 or not lengths[0].isascii()
                        or not lengths[0].isdigit() or len(lengths[0]) > 20):
                    raise HTTPException(400, 'Invalid Content-Length')
                if int(lengths[0]) > budget:
                    raise HTTPException(413, 'Evidence request exceeds size limit')

            received = 0
            exceeded = False

            async def bounded_receive():
                nonlocal received, exceeded
                message = await request.receive()
                if message['type'] == 'http.request':
                    received += len(message.get('body', b''))
                    if received > budget:
                        exceeded = True
                        # Starlette closes partially spooled files on this error.
                        # Do not forward the over-budget chunk to its parser.
                        raise MultiPartException('Evidence request exceeds size limit')
                return message

            bounded_request = Request(request.scope, receive=bounded_receive)
            try:
                return await handler(bounded_request)
            except StarletteHTTPException:
                if exceeded:
                    raise HTTPException(413, 'Evidence request exceeds size limit') from None
                raise

        return bounded_upload
