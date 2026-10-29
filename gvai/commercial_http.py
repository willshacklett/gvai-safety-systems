from __future__ import annotations

import http.client
import json
import math
import re
import select
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from gvai.commercial_service import (
    CommercialEvaluationService,
    CommercialServiceResponse,
    ServiceOutcome,
    ServiceReason,
)


HTTP_PATH = "/v1/evaluations"
MAX_BODY_BYTES = 16_384
MAX_HEADER_BYTES = 16_384
MAX_HEADER_COUNT = 32
DEFAULT_MAX_CONCURRENT_HANDLERS = 16
MAX_CONCURRENT_HANDLERS = 128
DEFAULT_REQUEST_TIMEOUT = 5.0
MAX_REQUEST_TIMEOUT = 60.0
_READ_CHUNK_BYTES = 4096
_RESOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CONTENT_LENGTH = re.compile(r"[0-9]{1,6}\Z")


class _BoundedHeaderReader:
    def __init__(self, stream: Any) -> None:
        self._stream = stream
        self._bytes_read = 0

    def readline(self, size: int = -1) -> bytes:
        remaining = MAX_HEADER_BYTES - self._bytes_read
        read_size = remaining + 1 if size < 0 else min(size, remaining + 1)
        line = self._stream.readline(read_size)
        self._bytes_read += len(line)
        if self._bytes_read > MAX_HEADER_BYTES:
            raise http.client.HTTPException("request headers exceed configured limit")
        return line


class _DeadlineReader:
    def __init__(self, connection: Any, deadline: float) -> None:
        self._connection = connection
        self._deadline = deadline
        self._buffer = bytearray()
        self._eof = False

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self._deadline

    def readline(self, size: int = -1) -> bytes:
        maximum = 65_537 if size < 0 else size
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                return self._consume(min(newline + 1, maximum))
            if len(self._buffer) >= maximum or self._eof:
                return self._consume(min(len(self._buffer), maximum))
            self._receive(min(_READ_CHUNK_BYTES, maximum - len(self._buffer)))

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            raise ValueError("unbounded reads are not supported")
        while len(self._buffer) < size and not self._eof:
            self._receive(min(_READ_CHUNK_BYTES, size - len(self._buffer)))
        return self._consume(min(size, len(self._buffer)))

    def prepare_write(self) -> None:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request deadline exceeded")
        self._connection.settimeout(remaining)

    def close(self) -> None:
        return

    def _receive(self, maximum: int) -> None:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request deadline exceeded")
        readable, _, _ = select.select([self._connection], [], [], remaining)
        if not readable:
            raise TimeoutError("request deadline exceeded")
        chunk = self._connection.recv(maximum)
        if chunk:
            self._buffer.extend(chunk)
        else:
            self._eof = True

    def _consume(self, size: int) -> bytes:
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result


def create_server(
    service: CommercialEvaluationService,
    port: int = 0,
    *,
    max_concurrent_handlers: int = DEFAULT_MAX_CONCURRENT_HANDLERS,
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
) -> ThreadingHTTPServer:
    """Create a local-only HTTP server around a trusted service instance."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port must be an integer between 0 and 65535")
    if (
        type(max_concurrent_handlers) is not int
        or not 1 <= max_concurrent_handlers <= MAX_CONCURRENT_HANDLERS
    ):
        raise ValueError("max_concurrent_handlers is outside the supported bound")
    if (
        type(request_timeout) not in (int, float)
        or not 0.05 <= request_timeout <= MAX_REQUEST_TIMEOUT
        or not math.isfinite(request_timeout)
    ):
        raise ValueError("request_timeout is outside the supported bound")
    handler = _handler_for(service)
    return _LocalThreadingHTTPServer(
        ("127.0.0.1", port), handler, max_concurrent_handlers, float(request_timeout)
    )


class _LocalThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler: type[BaseHTTPRequestHandler],
        max_concurrent_handlers: int,
        request_timeout: float,
    ) -> None:
        self._handler_slots = threading.BoundedSemaphore(max_concurrent_handlers)
        self.request_timeout = request_timeout
        super().__init__(server_address, request_handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._handler_slots.acquire(blocking=False):
            try:
                request.settimeout(0.1)
                body = (
                    b'{"error":{"code":"service_unavailable",'
                    b'"message":"Evaluation service is unavailable."}}'
                )
                response = (
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Type: application/json; charset=utf-8\r\n"
                    b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
                request.sendall(response)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._handler_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._handler_slots.release()

    def handle_error(self, request: object, client_address: object) -> None:
        return


def _handler_for(service: CommercialEvaluationService) -> type[BaseHTTPRequestHandler]:
    class EvaluationHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "GVAI-Local"
        sys_version = ""

        def setup(self) -> None:
            super().setup()
            self.rfile.close()
            self.connection.settimeout(None)
            self._deadline_reader = _DeadlineReader(
                self.connection, time.monotonic() + self.server.request_timeout
            )
            self.rfile = self._deadline_reader

        def parse_request(self) -> bool:
            original_stream = self.rfile
            self.rfile = _BoundedHeaderReader(original_stream)
            try:
                parsed = super().parse_request()
            finally:
                self.rfile = original_stream
            if not parsed:
                return False
            if self.headers.get_all("Expect"):
                self._write_error(
                    417, "expectation_not_supported", "Expect headers are not supported."
                )
                return False
            items = list(self.headers.raw_items())
            header_bytes = sum(len(name) + len(value) + 4 for name, value in items)
            if len(items) > MAX_HEADER_COUNT or header_bytes > MAX_HEADER_BYTES:
                self._write_error(
                    431, "headers_too_large", "Request headers are too large."
                )
                return False
            return True

        def handle_expect_100(self) -> bool:
            self._write_error(
                417, "expectation_not_supported", "Expect headers are not supported."
            )
            return False

        def do_POST(self) -> None:
            if self.path != HTTP_PATH:
                if "?" in self.path:
                    self._write_error(
                        400, "query_not_allowed", "Query strings are not accepted."
                    )
                else:
                    self._write_error(404, "not_found", "Endpoint not found.")
                return

            if not self._has_json_content_type():
                self._write_error(
                    415, "unsupported_media_type", "Content-Type must be application/json."
                )
                return
            if self.headers.get_all("Transfer-Encoding"):
                self._write_error(
                    400, "invalid_request", "Transfer-Encoding is not supported."
                )
                return
            if self.headers.get_all("Content-Encoding"):
                self._write_error(
                    415, "unsupported_media_type", "Content-Encoding is not supported."
                )
                return

            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) != 1 or _CONTENT_LENGTH.fullmatch(lengths[0]) is None:
                self._write_error(400, "invalid_request", "A valid Content-Length is required.")
                return
            body_length = int(lengths[0])
            if body_length > MAX_BODY_BYTES:
                self._write_error(413, "request_too_large", "Request body is too large.")
                return

            authorization = self.headers.get_all("Authorization") or []
            if len(authorization) != 1:
                self._write_error(
                    401, "authentication_required", "A bearer credential is required."
                )
                return
            scheme, separator, credential = authorization[0].partition(" ")
            if (
                not separator
                or scheme.lower() != "bearer"
                or not credential
                or any(character.isspace() for character in credential)
                or len(credential) > 4096
            ):
                self._write_error(
                    401, "authentication_required", "A bearer credential is required."
                )
                return

            try:
                raw_body = self.rfile.read(body_length)
                if len(raw_body) != body_length:
                    raise ValueError
                payload = json.loads(
                    raw_body.decode("utf-8"),
                    object_pairs_hook=_unique_object,
                    parse_constant=_reject_json_constant,
                )
                request = _validate_http_request(payload)
            except TimeoutError:
                self.close_connection = True
                return
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
                self._write_error(400, "invalid_request", "Request body is not valid v1 JSON.")
                return
            except Exception:
                self._write_error(400, "invalid_request", "Request body is not valid v1 JSON.")
                return

            if self._deadline_reader.expired:
                self.close_connection = True
                return

            try:
                result = service.evaluate(
                    credential,
                    request["resource_id"],
                    request["request_id"],
                    request["telemetry"],
                    request["reported_effects"],
                )
            except Exception:
                self._write_error(
                    503, "service_unavailable", "Evaluation service is unavailable."
                )
                return

            if type(result) is not CommercialServiceResponse:
                self._write_error(
                    503, "service_unavailable", "Evaluation service is unavailable."
                )
                return

            if result.outcome is ServiceOutcome.EVALUATED and result.reason is ServiceReason.EVALUATED:
                try:
                    self._send_json(200, result.to_dict())
                except Exception:
                    self._write_error(500, "internal_error", "Evaluation response unavailable.")
                return

            errors = {
                ServiceReason.INVALID_REQUEST: (
                    400, "invalid_request", "Request does not match the v1 schema."
                ),
                ServiceReason.AUTHORIZATION_DENIED: (
                    403, "authorization_denied", "Credential is not authorized for this resource."
                ),
                ServiceReason.QUOTA_DENIED: (
                    429, "quota_denied", "Evaluation quota is unavailable."
                ),
                ServiceReason.REPLAY: (
                    409, "replay", "This request ID has already been used."
                ),
                ServiceReason.ACCOUNTING_FAILURE: (
                    503, "accounting_failure", "Evaluation accounting is unavailable."
                ),
                ServiceReason.EVALUATION_FAILURE: (
                    500, "evaluation_failure", "Evaluation could not be completed."
                ),
            }
            error = errors.get(result.reason)
            if error is None:
                self._write_error(500, "internal_error", "Evaluation could not be completed.")
                return
            status, code, message = error
            self._write_error(status, code, message)

        def do_GET(self) -> None:
            self._method_not_allowed()

        def do_HEAD(self) -> None:
            self._method_not_allowed()

        def do_PUT(self) -> None:
            self._method_not_allowed()

        def do_PATCH(self) -> None:
            self._method_not_allowed()

        def do_DELETE(self) -> None:
            self._method_not_allowed()

        def do_OPTIONS(self) -> None:
            self._method_not_allowed()

        def do_CONNECT(self) -> None:
            self._method_not_allowed()

        def do_TRACE(self) -> None:
            self._method_not_allowed()

        def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
            if code == 501:
                self._method_not_allowed()
            elif code == 431:
                self._write_error(
                    431, "headers_too_large", "Request headers are too large."
                )
            elif code == 414:
                self._write_error(414, "request_too_large", "Request line is too large.")
            else:
                self._write_error(code, "invalid_http_request", "HTTP request is invalid.")

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _method_not_allowed(self) -> None:
            self._write_error(
                405,
                "method_not_allowed",
                "Only POST is supported.",
                allow="POST",
            )

        def _has_json_content_type(self) -> bool:
            values = self.headers.get_all("Content-Type") or []
            return len(values) == 1 and values[0].strip().lower() == "application/json"

        def _write_error(
            self,
            status: int,
            code: str,
            message: str,
            *,
            allow: str | None = None,
        ) -> None:
            self._send_json(status, {"error": {"code": code, "message": message}}, allow=allow)

        def _send_json(
            self, status: int, payload: dict[str, Any], *, allow: str | None = None
        ) -> None:
            self._deadline_reader.prepare_write()
            body = json.dumps(
                payload, allow_nan=False, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            if allow is not None:
                self.send_header("Allow", allow)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

    return EvaluationHandler


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _validate_http_request(payload: object) -> dict[str, Any]:
    fields = {"version", "request_id", "resource_id", "telemetry", "reported_effects"}
    if type(payload) is not dict or set(payload) != fields:
        raise ValueError("request fields do not match v1")
    if type(payload["version"]) is not str or payload["version"] != "v1":
        raise ValueError("unsupported request version")
    if (
        type(payload["resource_id"]) is not str
        or _RESOURCE_ID.fullmatch(payload["resource_id"]) is None
    ):
        raise ValueError("invalid resource identifier")
    return payload
