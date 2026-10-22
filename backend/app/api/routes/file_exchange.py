"""Bounded in-memory HTTP endpoints for `.qshield` file exchange."""

from __future__ import annotations

import re
from codecs import lookup as lookup_codec
from email import policy
from email.message import Message
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from python_multipart.exceptions import FormParserError, MultipartParseError
from python_multipart.multipart import MultipartParser

from backend.app.api.dependencies import get_file_exchange_service
from backend.app.file_exchange.protocol import MAX_FILE_SIZE, MAX_PACKAGE_SIZE
from backend.app.services.file_exchange_service import (
    FileExchangeInputError,
    FileExchangeMissingRecord,
    FileExchangePrivateKeyUnavailable,
    FileExchangeService,
    FileExchangeUnlockRateLimited,
    FileExchangeUntrustedSender,
)

router = APIRouter(tags=["file exchange"])
_KEY_ID = re.compile(r"^[0-9a-f]{64}$")
_MAX_PASSPHRASE_BYTES = 4096
_MAX_FORM_VALUE_BYTES = 256
_BOUNDARY = re.compile(r"^[0-9A-Za-z'()+_,./:=?-]{1,70}$")
_MAX_MULTIPART_PARTS = 4
_MAX_MULTIPART_HEADERS = 8
_MAX_MULTIPART_HEADER_LINE_BYTES = 8192
_MAX_MULTIPART_HEADERS_BYTES = 16 * 1024


@router.post("/encrypt")
async def encrypt_file(
    request: Request,
    service: FileExchangeService = Depends(get_file_exchange_service),
) -> Response:
    form = await _multipart(request, {"file", "recipient_key_id", "signing_key_id", "passphrase"})
    filename, content = _file_field(form)
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="file exceeds the permitted size")
    recipient_id = _key_field(form, "recipient_key_id")
    signing_id = _key_field(form, "signing_key_id")
    passphrase = _passphrase_field(form)
    try:
        package = service.create_package(filename, content, recipient_id, signing_id, passphrase)
    except FileExchangeUnlockRateLimited as exc:
        raise HTTPException(status_code=429, detail="private-key operation is temporarily unavailable") from exc
    except FileExchangePrivateKeyUnavailable as exc:
        raise HTTPException(status_code=400, detail="selected private key is unavailable") from exc
    except FileExchangeMissingRecord as exc:
        raise HTTPException(status_code=404, detail="selected key was not found") from exc
    except FileExchangeUntrustedSender as exc:
        raise HTTPException(status_code=400, detail="selected recipient key is unavailable") from exc
    except FileExchangeInputError as exc:
        raise HTTPException(status_code=400, detail="package could not be created") from exc
    return Response(
        package,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="package.qshield"'},
    )


@router.post("/verify")
async def verify_file(
    request: Request,
    service: FileExchangeService = Depends(get_file_exchange_service),
) -> dict[str, object]:
    form = await _multipart(request, {"file", "sender_key_id"})
    _, package = _file_field(form)
    if len(package) > MAX_PACKAGE_SIZE:
        raise HTTPException(status_code=413, detail="package exceeds the permitted size")
    sender_id = _key_field(form, "sender_key_id")
    try:
        verified = service.verify_package(package, sender_id)
    except FileExchangeMissingRecord as exc:
        raise HTTPException(status_code=404, detail="trusted sender key was not found") from exc
    except FileExchangeUntrustedSender as exc:
        raise HTTPException(status_code=403, detail="sender is not trusted or signature is invalid") from exc
    except FileExchangeInputError as exc:
        raise HTTPException(status_code=400, detail="package is invalid") from exc
    header = verified.package.header
    return {
        "verified": True,
        "sender_key_id": verified.sender_key_id,
        "recipient_key_id": header.recipient_key_id.hex(),
        "created_at": header.created_at,
    }


@router.post("/decrypt")
async def decrypt_file(
    request: Request,
    service: FileExchangeService = Depends(get_file_exchange_service),
) -> Response:
    form = await _multipart(request, {"file", "recipient_key_id", "sender_key_id", "passphrase"})
    _, package = _file_field(form)
    if len(package) > MAX_PACKAGE_SIZE:
        raise HTTPException(status_code=413, detail="package exceeds the permitted size")
    recipient_id = _key_field(form, "recipient_key_id")
    sender_id = _key_field(form, "sender_key_id")
    passphrase = _passphrase_field(form)
    try:
        filename, plaintext = service.decrypt_package(package, recipient_id, sender_id, passphrase)
    except FileExchangeUnlockRateLimited as exc:
        raise HTTPException(status_code=429, detail="private-key operation is temporarily unavailable") from exc
    except FileExchangePrivateKeyUnavailable as exc:
        raise HTTPException(status_code=400, detail="selected private key is unavailable") from exc
    except FileExchangeMissingRecord as exc:
        raise HTTPException(status_code=404, detail="selected key was not found") from exc
    except FileExchangeUntrustedSender as exc:
        raise HTTPException(status_code=403, detail="sender is not trusted or signature is invalid") from exc
    except FileExchangeInputError as exc:
        raise HTTPException(status_code=400, detail="package could not be decrypted") from exc
    # The protocol parser has already rejected path separators and unsafe names.
    disposition_name = quote(filename, safe="")
    return Response(
        plaintext,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{disposition_name}"},
    )


async def _multipart(request: Request, expected_fields: set[str]) -> dict[str, tuple[str | None, bytes]]:
    content_type_values = request.headers.getlist("content-type")
    if len(content_type_values) != 1:
        await _drain_request_body(request)
        raise HTTPException(status_code=400, detail="malformed multipart request")
    try:
        content_type_text = content_type_values[0]
        _validate_mime_header("Content-Type", content_type_text)
        content_type = Message()
        content_type["Content-Type"] = content_type_text
        content_type_params = content_type.get_params(
            header="Content-Type", unquote=True
        )
        boundary_values = [
            value for name, value in content_type_params[1:]
            if name.lower() == "boundary"
        ]
    except (TypeError, ValueError):
        await _drain_request_body(request)
        raise HTTPException(status_code=400, detail="malformed multipart request") from None
    boundary = boundary_values[0] if len(boundary_values) == 1 else None
    if (
        content_type.get_content_type() != "multipart/form-data"
        or not isinstance(boundary, str)
        or not _BOUNDARY.fullmatch(boundary)
    ):
        await _drain_request_body(request)
        raise HTTPException(status_code=400, detail="malformed multipart request")

    file_limit = MAX_FILE_SIZE if "signing_key_id" in expected_fields else MAX_PACKAGE_SIZE
    field_limits = {
        "file": file_limit,
        "recipient_key_id": _MAX_FORM_VALUE_BYTES,
        "signing_key_id": _MAX_FORM_VALUE_BYTES,
        "sender_key_id": _MAX_FORM_VALUE_BYTES,
        "passphrase": _MAX_PASSPHRASE_BYTES,
    }
    fields: dict[str, tuple[str | None, bytes]] = {}
    current_name: str | None = None
    current_filename: str | None = None
    current_value = bytearray()
    current_headers: dict[bytes, bytes] = {}
    current_header_name = bytearray()
    current_header_value = bytearray()
    current_header_bytes = 0
    part_count = 0
    saw_closing_boundary = False

    def fail(detail: str = "malformed multipart request", status_code: int = 400) -> None:
        raise _MultipartCallbackError(detail, status_code)

    def on_part_begin() -> None:
        nonlocal part_count, current_name, current_filename, current_value
        nonlocal current_headers, current_header_bytes
        part_count += 1
        if part_count > min(_MAX_MULTIPART_PARTS, len(expected_fields)):
            fail("unexpected or duplicate multipart field")
        current_name = None
        current_filename = None
        current_value = bytearray()
        current_headers = {}
        current_header_bytes = 0

    def on_header_begin() -> None:
        nonlocal current_header_name, current_header_value
        current_header_name = bytearray()
        current_header_value = bytearray()

    def append_header(target: bytearray, data: bytes, start: int, end: int) -> None:
        nonlocal current_header_bytes
        size = end - start
        current_header_bytes += size
        if (
            len(target) + size > _MAX_MULTIPART_HEADER_LINE_BYTES
            or current_header_bytes > _MAX_MULTIPART_HEADERS_BYTES
        ):
            fail("malformed multipart request")
        target.extend(data[start:end])

    def on_header_field(data: bytes, start: int, end: int) -> None:
        append_header(current_header_name, data, start, end)

    def on_header_value(data: bytes, start: int, end: int) -> None:
        append_header(current_header_value, data, start, end)

    def on_header_end() -> None:
        nonlocal current_header_bytes
        name = bytes(current_header_name).lower()
        if not name or name in current_headers:
            fail("malformed multipart field")
        current_headers[name] = bytes(current_header_value)
        # Include the field/value separator and CRLF in the aggregate cap.
        current_header_bytes += 4
        if current_header_bytes > _MAX_MULTIPART_HEADERS_BYTES:
            fail("malformed multipart request")

    def on_headers_finished() -> None:
        nonlocal current_name, current_filename
        if b"content-transfer-encoding" in current_headers:
            fail("malformed multipart field")
        disposition_value = current_headers.get(b"content-disposition")
        if disposition_value is None:
            fail("malformed multipart field")
        content_type_value = current_headers.get(b"content-type")
        if content_type_value is not None:
            try:
                content_type_text = content_type_value.decode("ascii")
                _validate_mime_header("Content-Type", content_type_text)
                content_type_message = Message()
                content_type_message["Content-Type"] = content_type_text
            except (UnicodeDecodeError, TypeError, ValueError):
                fail("malformed multipart field")
            if content_type_message.get_content_maintype().lower() == "multipart":
                fail("malformed multipart field")
        try:
            # HTTP clients commonly send UTF-8 filename bytes directly. Decode
            # those first, retaining Latin-1 compatibility for other headers.
            try:
                disposition_text = disposition_value.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                disposition_text = disposition_value.decode("latin-1")
            _validate_mime_header("Content-Disposition", disposition_text)
            disposition_message = Message()
            disposition_message["Content-Disposition"] = disposition_text
            params = disposition_message.get_params(
                header="Content-Disposition", unquote=True
            )
            if not params or params[0][0].lower() != "form-data":
                fail("malformed multipart field")
            name_values = [value for key, value in params[1:] if key.lower() == "name"]
            filename_values = [value for key, value in params[1:] if key.lower() == "filename"]
            if len(name_values) != 1 or len(filename_values) > 1:
                fail("malformed multipart field")
            name_value = name_values[0]
            filename_value = filename_values[0] if filename_values else None
            # Compat32 retains repeated RFC 2231 parameters and returns their
            # octets represented through Latin-1. Decode those octets using
            # the declared charset instead of accepting email's lossy fallback.
            if isinstance(name_value, tuple) and len(name_value) == 3:
                name_value = _decode_rfc2231_value(name_value)
            if isinstance(filename_value, tuple) and len(filename_value) == 3:
                filename_value = _decode_rfc2231_value(filename_value)
            if not isinstance(name_value, str) or name_value not in expected_fields:
                fail("unexpected or duplicate multipart field")
            if name_value in fields:
                fail("unexpected or duplicate multipart field")
            if filename_value is not None and not isinstance(filename_value, str):
                fail("malformed multipart field")
            current_name = name_value
            current_filename = filename_value
        except (TypeError, ValueError, UnicodeError, LookupError):
            fail("malformed multipart field")

    def on_part_data(data: bytes, start: int, end: int) -> None:
        if current_name is None:
            fail("malformed multipart field")
        maximum = field_limits[current_name]
        if len(current_value) + (end - start) > maximum:
            if current_name == "file":
                detail = "file exceeds the permitted size" if file_limit == MAX_FILE_SIZE else "package exceeds the permitted size"
                fail(detail, 413)
            fail("invalid multipart field")
        current_value.extend(data[start:end])

    def on_part_end() -> None:
        nonlocal current_value
        if current_name is None:
            fail("malformed multipart field")
        fields[current_name] = (current_filename, bytes(current_value))
        current_value.clear()

    def on_end() -> None:
        nonlocal saw_closing_boundary
        saw_closing_boundary = True

    parser = MultipartParser(
        boundary.encode("ascii"),
        {
            "on_part_begin": on_part_begin,
            "on_header_begin": on_header_begin,
            "on_header_field": on_header_field,
            "on_header_value": on_header_value,
            "on_header_end": on_header_end,
            "on_headers_finished": on_headers_finished,
            "on_part_data": on_part_data,
            "on_part_end": on_part_end,
            "on_end": on_end,
        },
        max_header_count=_MAX_MULTIPART_HEADERS,
        max_header_size=_MAX_MULTIPART_HEADER_LINE_BYTES,
    )
    # python-multipart signals on_end at the second closing hyphen and then
    # discards the remainder of the current write as epilogue. Observe the
    # exact delimiter offset alongside each write so this adapter can require
    # its CRLF line ending while the maintained parser validates multipart.
    closing_marker = b"\r\n--" + boundary.encode("ascii") + b"--"
    scan_tail = b""
    closing_line = bytearray()
    closing_line_valid = False
    parse_error: _MultipartCallbackError | None = None

    def consume_epilogue(data: bytes, offset: int = 0) -> None:
        nonlocal closing_line_valid
        if closing_line_valid:
            return
        needed = 2 - len(closing_line)
        closing_line.extend(data[offset : offset + needed])
        if len(closing_line) == 2:
            if bytes(closing_line) != b"\r\n":
                fail("malformed multipart request")
            closing_line_valid = True

    def feed_parser_chunk(chunk: bytes) -> None:
        nonlocal scan_tail
        if saw_closing_boundary:
            consume_epilogue(chunk)
            return

        # Detect a closing delimiter split across ASGI chunks. The parser has
        # already received scan_tail; it is retained only for this bounded
        # delimiter comparison, not for replay or body reconstruction.
        crossing_end = None
        max_overlap = min(len(scan_tail), len(closing_marker) - 1, len(chunk))
        for overlap in range(max_overlap, 0, -1):
            if (
                scan_tail[-overlap:] == closing_marker[:overlap]
                and chunk.startswith(closing_marker[overlap:])
            ):
                crossing_end = len(closing_marker) - overlap
                break

        marker_start = chunk.find(closing_marker)
        marker_end = marker_start + len(closing_marker) if marker_start >= 0 else None
        if crossing_end is not None and (marker_end is None or crossing_end < marker_end):
            marker_end = crossing_end

        # Pass the original ASGI chunk once; the scanner retains no body data
        # and does not create a large prefix copy when a delimiter is near EOF.
        parser.write(chunk)
        if saw_closing_boundary:
            if marker_end is None:
                fail("malformed multipart request")
            consume_epilogue(chunk, marker_end)
            scan_tail = b""
            return
        if len(closing_marker) > 1:
            tail_size = len(closing_marker) - 1
            if len(chunk) >= tail_size:
                scan_tail = chunk[-tail_size:]
            else:
                scan_tail = (scan_tail + chunk)[-tail_size:]

    async for chunk in request.stream():
        if parse_error is None:
            try:
                feed_parser_chunk(chunk)
            except (_MultipartCallbackError, MultipartParseError, FormParserError) as exc:
                # Do not retain partially parsed data after an error. Continue
                # reading so middleware still enforces the streamed body cap.
                fields.clear()
                current_value.clear()
                current_headers.clear()
                parse_error = exc if isinstance(exc, _MultipartCallbackError) else _MultipartCallbackError(
                    "malformed multipart request", 400
                )
    if parse_error is None:
        try:
            parser.finalize()
        except (_MultipartCallbackError, MultipartParseError, FormParserError) as exc:
            fields.clear()
            parse_error = _MultipartCallbackError("malformed multipart request", 400)
            parse_error.__cause__ = exc
    if parse_error is None and saw_closing_boundary and not closing_line_valid:
        parse_error = _MultipartCallbackError("malformed multipart request", 400)
    if parse_error is not None:
        raise HTTPException(status_code=parse_error.status_code, detail=parse_error.detail) from parse_error
    if not saw_closing_boundary:
        raise HTTPException(status_code=400, detail="malformed multipart request")
    if set(fields) != expected_fields:
        raise HTTPException(status_code=400, detail="required multipart fields are missing")
    return fields


class _MultipartCallbackError(Exception):
    def __init__(self, detail: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def _validate_mime_header(header_name: str, value: str) -> None:
    """Reject parser defects and duplicate parameters before using MIME values."""
    strict_message = Message(policy=policy.default)
    strict_message[header_name] = value
    parsed_header = strict_message[header_name]
    if getattr(parsed_header, "defects", ()):
        raise ValueError("defective MIME header")

    # The compat32 parameter parser retains duplicate occurrences that the
    # modern policy parser may omit after recording a defect. Check both views.
    strict_params = strict_message.get_params(header=header_name, unquote=True)
    compat_message = Message()
    compat_message[header_name] = value
    compat_params = compat_message.get_params(header=header_name, unquote=True)
    if not strict_params or not compat_params:
        raise ValueError("malformed MIME parameters")
    for parameters in (strict_params[1:], compat_params[1:]):
        names = [name.lower() for name, _ in parameters]
        if len(names) != len(set(names)):
            raise ValueError("duplicate MIME parameter")


def _decode_rfc2231_value(value: tuple[str, str, str]) -> str:
    charset, _language, encoded_value = value
    codec = lookup_codec(charset or "us-ascii")
    return encoded_value.encode("latin-1", errors="strict").decode(codec.name, errors="strict")


async def _drain_request_body(request: Request) -> None:
    """Consume rejected-header requests so middleware can enforce streamed limits."""
    async for _ in request.stream():
        pass


def _file_field(fields: dict[str, tuple[str | None, bytes]]) -> tuple[str, bytes]:
    filename, payload = fields["file"]
    if filename is None or not filename:
        raise HTTPException(status_code=400, detail="file name is required")
    return filename, payload


def _text_field(fields: dict[str, tuple[str | None, bytes]], name: str, maximum: int) -> str:
    filename, payload = fields[name]
    if filename is not None or not payload or len(payload) > maximum:
        raise HTTPException(status_code=400, detail="invalid multipart field")
    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid multipart field") from exc


def _key_field(fields: dict[str, tuple[str | None, bytes]], name: str) -> str:
    value = _text_field(fields, name, _MAX_FORM_VALUE_BYTES)
    if not _KEY_ID.fullmatch(value):
        raise HTTPException(status_code=400, detail="invalid key identifier")
    return value


def _passphrase_field(fields: dict[str, tuple[str | None, bytes]]) -> str:
    value = _text_field(fields, "passphrase", _MAX_PASSPHRASE_BYTES)
    if len(value) > 1024:
        raise HTTPException(status_code=400, detail="invalid passphrase")
    return value
