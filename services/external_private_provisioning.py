# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import re
import secrets
from typing import Any, Callable, Literal
from urllib.parse import quote, urlparse

from sqlalchemy import delete, func, insert, or_, select, update
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError, OperationalError
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import RequestEntityTooLarge

from course_categories import normalize_category_slugs
from functions.database import (
    acquire_private_provisioning_identity_locks,
    company_users_table,
    external_provisioning_nonces_table,
    external_provisioning_requests_table,
    get_engine,
    pending_supervisors_table,
    pending_users_table,
    private_account_activation_tokens_table,
    supervisor_connections_table,
    supervisors_table,
    user_pdfs_table,
    users_table,
)
from functions.emails import service as email_service
from functions.hashing import (
    _is_valid_hash,
    email_lookup_values,
    hash_password,
    hash_value,
    normalize_email,
    normalize_personnummer,
)
from functions.logging import configure_module_logger, mask_hash
from services.pdf_scanner import (
    PDFScannerExecutionError,
    PDFScannerTimeoutError,
    PDFScannerUnavailableError,
    ScanVerdict,
    scan_pdf_bytes,
)


logger = configure_module_logger(__name__)

EXTERNAL_ROUTE = "/api/external/private-account-provisioning"
EXPECTED_FORM_FIELDS = frozenset(
    {
        "personal_identity_number",
        "email",
        "name",
        "expires_at",
        "category",
    }
)
EXPECTED_FILE_FIELDS = frozenset({"pdf"})
REQUIRED_HEADERS = (
    "X-External-Key-Id",
    "X-External-Timestamp",
    "X-External-Nonce",
    "Idempotency-Key",
    "X-External-Pdf-Sha256",
    "X-External-Signature",
)
TERMINAL_STATES = frozenset(
    {"completed", "failed_terminal", "delivery_unknown"}
)
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$")
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[\x21-\x7e]{8,200}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
SIGNATURE_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
MAX_NAME_LENGTH = 200
DEFAULT_MAX_PDF_BYTES = 10 * 1024 * 1024
MAX_ALLOWED_EXTERNAL_PDF_BYTES = 49 * 1024 * 1024
DEFAULT_LOCK_TIMEOUT_SECONDS = 120
DEFAULT_TIMESTAMP_WINDOW_SECONDS = 300
DEFAULT_NONCE_TTL_HOURS = 24
DEFAULT_ACTIVATION_TTL_HOURS = 48

ClaimMode = Literal["initial", "mail_retry"]


@dataclass(frozen=True)
class ExternalResponse:
    http_status: int
    body: dict[str, Any]
    body_text: str


@dataclass(frozen=True)
class NormalizedProvisioningRequest:
    key_id: str
    secret: bytes
    timestamp: str
    nonce: str
    idempotency_key: str
    expected_pdf_sha256: str
    request_fingerprint: str
    idempotency_key_hash: str
    nonce_hash: str
    personal_identity_number: str
    personnummer_hash: str
    email: str
    name: str
    expires_on: date | None
    expires_at_fingerprint: str
    category: str
    file_storage: FileStorage


@dataclass(frozen=True)
class RequestClaim:
    request_id: int
    attempt_count: int
    mode: ClaimMode


@dataclass(frozen=True)
class AccountResolution:
    state: Literal["active", "pending"]
    personnummer_hash: str
    recipient_email: str | None
    recipient_name: str
    activation_required: bool


@dataclass(frozen=True)
class MailContext:
    request_id: int
    attempt_count: int
    idempotency_key_hash: str
    account_state: str
    recipient_email: str
    recipient_name: str
    filename: str
    pdf_content: bytes
    activation_token: str | None


@dataclass(frozen=True)
class ActivationTokenStatus:
    valid: bool
    token_hash: str | None = None


class ProvisioningAPIError(Exception):
    def __init__(
        self,
        http_status: int,
        code: str,
        message: str,
        *,
        terminal: bool = True,
    ) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.code = code
        self.message = message
        self.terminal = terminal


class RequestLeaseLostError(RuntimeError):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _as_bool(value: str | None) -> bool:
    return (value or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
        "ja",
        "sant",
    }


def external_provisioning_enabled() -> bool:
    return _as_bool(os.getenv("EXTERNAL_PRIVATE_PROVISIONING_ENABLED"))


def _json_object_without_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(
                "EXTERNAL_PROVISIONING_HMAC_KEYS innehåller dubbla key_id."
            )
        result[key] = value
    return result


def load_hmac_keys() -> dict[str, bytes]:
    raw = (
        os.getenv("EXTERNAL_PROVISIONING_HMAC_KEYS")
        or os.getenv("EXTERNAL_PRIVATE_PROVISIONING_KEYS")
        or ""
    ).strip()
    if not raw:
        raise ValueError(
            "EXTERNAL_PROVISIONING_HMAC_KEYS måste anges när integrationen är aktiv."
        )

    entries: list[tuple[str, str]]
    if raw.startswith("{"):
        try:
            parsed = json.loads(
                raw,
                object_pairs_hook=_json_object_without_duplicate_keys,
            )
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(
                "EXTERNAL_PROVISIONING_HMAC_KEYS måste vara giltig JSON."
            ) from exc
        if not isinstance(parsed, dict):
            raise ValueError(
                "EXTERNAL_PROVISIONING_HMAC_KEYS måste vara ett JSON-objekt."
            )
        entries = [(str(key), str(value)) for key, value in parsed.items()]
    else:
        entries = []
        for part in raw.split(","):
            if "=" not in part:
                raise ValueError(
                    "HMAC-nycklar måste anges som JSON eller key_id=hemlighet."
                )
            key_id, secret_value = part.split("=", 1)
            entries.append((key_id, secret_value))

    configured_minimum = int(
        os.getenv("EXTERNAL_PROVISIONING_MIN_SECRET_LENGTH", "32")
    )
    minimum_length = max(32, configured_minimum)
    keys: dict[str, bytes] = {}
    for raw_key_id, raw_secret in entries:
        key_id = raw_key_id.strip()
        secret_value = raw_secret.strip()
        if not key_id or not KEY_ID_PATTERN.fullmatch(key_id):
            raise ValueError(
                "Varje external key_id måste vara unikt och ha ett giltigt format."
            )
        if key_id in keys:
            raise ValueError(
                "EXTERNAL_PROVISIONING_HMAC_KEYS innehåller dubbla key_id."
            )
        secret_bytes = secret_value.encode("utf-8")
        if len(secret_bytes) < minimum_length:
            raise ValueError(
                "Varje HMAC-hemlighet måste vara minst "
                f"{minimum_length} byte lång."
            )
        keys[key_id] = secret_bytes

    if not keys:
        raise ValueError("Minst en extern HMAC-nyckel måste konfigureras.")
    return keys


def validate_startup_configuration() -> None:
    if not external_provisioning_enabled():
        return
    load_hmac_keys()
    _external_pdf_max_bytes()
    _public_base_url()
    if not _as_bool(os.getenv("DEV_MODE")):
        if email_service.should_disable_email_sending():
            raise RuntimeError(
                "External provisioning kan inte aktiveras i produktion när "
                "DISABLE_EMAILS=true."
            )
        secure_cookie_value = os.getenv("SESSION_COOKIE_SECURE")
        secure_cookie_enabled = (
            True
            if secure_cookie_value is None
            else _as_bool(secure_cookie_value)
        )
        if not secure_cookie_enabled:
            raise RuntimeError(
                "External provisioning kräver SESSION_COOKIE_SECURE=true "
                "i produktion."
            )


def _public_base_url() -> str:
    base_url = (os.getenv("BASE_URL") or "").strip().rstrip("/")
    parsed = urlparse(base_url)
    allowed_schemes = {"http", "https"} if _as_bool(
        os.getenv("DEV_MODE")
    ) else {"https"}
    if (
        parsed.scheme not in allowed_schemes
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "BASE_URL måste vara en betrodd publik HTTPS-adress när "
            "external provisioning är aktiv."
        )
    return base_url


def build_activation_url(raw_token: str) -> str:
    token_path = quote(raw_token, safe="-_~")
    return f"{_public_base_url()}/create_user/token/{token_path}"


def _external_pdf_max_bytes() -> int:
    raw = os.getenv(
        "EXTERNAL_PROVISIONING_MAX_PDF_BYTES",
        str(DEFAULT_MAX_PDF_BYTES),
    )
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(
            "EXTERNAL_PROVISIONING_MAX_PDF_BYTES måste vara ett heltal."
        ) from exc
    if value <= 0 or value > MAX_ALLOWED_EXTERNAL_PDF_BYTES:
        raise ValueError(
            "EXTERNAL_PROVISIONING_MAX_PDF_BYTES måste vara större än noll "
            "och lägre än den globala uppladdningsgränsen."
        )
    return value


def _lock_timeout() -> timedelta:
    raw = os.getenv(
        "EXTERNAL_PROVISIONING_LOCK_TIMEOUT_SECONDS",
        str(DEFAULT_LOCK_TIMEOUT_SECONDS),
    )
    return timedelta(seconds=max(60, int(raw)))


def _activation_ttl() -> timedelta:
    raw = os.getenv(
        "EXTERNAL_PROVISIONING_ACTIVATION_TTL_HOURS",
        str(DEFAULT_ACTIVATION_TTL_HOURS),
    )
    return timedelta(hours=max(1, int(raw)))


def _response(
    http_status: int,
    status: str,
    code: str,
    message: str,
    **extra: Any,
) -> ExternalResponse:
    body: dict[str, Any] = {
        "status": status,
        "code": code,
        "message": message,
    }
    body.update(extra)
    body_text = json.dumps(
        body,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return ExternalResponse(http_status, body, body_text)


def error_response(
    http_status: int,
    code: str,
    message: str,
    **extra: Any,
) -> ExternalResponse:
    return _response(http_status, "error", code, message, **extra)


def success_response(
    code: str,
    message: str,
    **extra: Any,
) -> ExternalResponse:
    return _response(201, "success", code, message, **extra)


def _response_from_stored(
    http_status: int | None,
    response_body: str | None,
) -> ExternalResponse:
    if http_status is None or not response_body:
        return error_response(
            500,
            "invalid_request_state",
            "Integrationsbegärans sparade svar är ofullständigt.",
        )
    try:
        body = json.loads(response_body)
    except json.JSONDecodeError:
        return error_response(
            500,
            "invalid_request_state",
            "Integrationsbegärans sparade svar är ogiltigt.",
        )
    if not isinstance(body, dict):
        return error_response(
            500,
            "invalid_request_state",
            "Integrationsbegärans sparade svar är ogiltigt.",
        )
    return ExternalResponse(int(http_status), body, response_body)


def _normalize_name(value: str) -> str:
    normalized = " ".join((value or "").split())
    if not normalized:
        raise ProvisioningAPIError(
            400,
            "invalid_name",
            "Fältet name måste innehålla ett namn.",
        )
    if len(normalized) > MAX_NAME_LENGTH:
        raise ProvisioningAPIError(
            400,
            "invalid_name",
            f"Fältet name får vara högst {MAX_NAME_LENGTH} tecken.",
        )
    return normalized


def _parse_expiry(value: str) -> tuple[date | None, str]:
    normalized = (value or "").strip()
    if not normalized:
        return None, ""
    try:
        parsed = date.fromisoformat(normalized)
    except ValueError as exc:
        raise ProvisioningAPIError(
            400,
            "invalid_expires_at",
            "Fältet expires_at måste vara ett ISO-datum i formatet ÅÅÅÅ-MM-DD.",
        ) from exc
    return parsed, parsed.isoformat()


def build_request_fingerprint(
    personal_identity_number: str,
    email: str,
    name: str,
    expires_at: str,
    category: str,
    pdf_sha256: str,
) -> str:
    normalized_pnr = normalize_personnummer(personal_identity_number)
    normalized_email = normalize_email(email)
    normalized_name = _normalize_name(name)
    _expiry, normalized_expiry = _parse_expiry(expires_at)
    normalized_categories = normalize_category_slugs([category])
    if len(normalized_categories) != 1:
        raise ProvisioningAPIError(
            400,
            "invalid_category",
            "Fältet category måste innehålla en giltig kurskategori.",
        )
    normalized_pdf_hash = (pdf_sha256 or "").strip().lower()
    if not SHA256_PATTERN.fullmatch(normalized_pdf_hash):
        raise ProvisioningAPIError(
            400,
            "invalid_pdf_hash",
            "X-External-Pdf-Sha256 måste vara en SHA-256-hash.",
        )
    canonical_business_fields = {
        "category": normalized_categories[0],
        "email": normalized_email,
        "expires_at": normalized_expiry,
        "name": normalized_name,
        "pdf_sha256": normalized_pdf_hash,
        "personal_identity_number": normalized_pnr,
    }
    canonical_json = json.dumps(
        canonical_business_fields,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def build_canonical_signature_payload(
    *,
    key_id: str,
    timestamp: str,
    nonce: str,
    idempotency_key: str,
    request_fingerprint: str,
) -> str:
    return "\n".join(
        (
            "POST",
            EXTERNAL_ROUTE,
            key_id,
            timestamp,
            nonce,
            idempotency_key,
            request_fingerprint,
        )
    )


def calculate_signature(
    secret: str | bytes,
    *,
    key_id: str,
    timestamp: str,
    nonce: str,
    idempotency_key: str,
    request_fingerprint: str,
) -> str:
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    payload = build_canonical_signature_payload(
        key_id=key_id,
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=idempotency_key,
        request_fingerprint=request_fingerprint,
    )
    return hmac.new(
        secret_bytes,
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _identifier_hash(secret: bytes, context: str, value: str) -> str:
    return hmac.new(
        secret,
        f"{context}\0{value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _single_header(headers: Any, name: str) -> str:
    values = headers.getlist(name)
    if len(values) != 1:
        raise ProvisioningAPIError(
            400,
            "duplicate_header",
            f"Headern {name} får anges exakt en gång.",
        )
    value = str(values[0]).strip()
    if not value:
        raise ProvisioningAPIError(
            400,
            "missing_header",
            f"Headern {name} måste anges.",
        )
    if "," in value:
        raise ProvisioningAPIError(
            400,
            "duplicate_header",
            f"Headern {name} får anges exakt en gång.",
        )
    return value


def _validate_timestamp(raw_timestamp: str, now: datetime) -> None:
    if not raw_timestamp.isascii() or not raw_timestamp.isdigit():
        raise ProvisioningAPIError(
            400,
            "invalid_timestamp",
            "X-External-Timestamp måste vara Unix-tid i hela sekunder.",
        )
    try:
        timestamp_value = int(raw_timestamp)
        request_time = datetime.fromtimestamp(timestamp_value, timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ProvisioningAPIError(
            400,
            "invalid_timestamp",
            "X-External-Timestamp innehåller ett ogiltigt tidsvärde.",
        ) from exc
    allowed_window = timedelta(
        seconds=DEFAULT_TIMESTAMP_WINDOW_SECONDS
    )
    if abs(now - request_time) > allowed_window:
        raise ProvisioningAPIError(
            401,
            "timestamp_outside_window",
            "Begärans tidsstämpel ligger utanför det tillåtna tidsfönstret.",
        )


def _extract_single_form_value(form: Any, field_name: str) -> str:
    values = form.getlist(field_name)
    if len(values) != 1:
        raise ProvisioningAPIError(
            400,
            "duplicate_field",
            f"Fältet {field_name} måste anges exakt en gång.",
        )
    return str(values[0])


def _normalize_http_request(http_request: Any) -> NormalizedProvisioningRequest:
    if http_request.mimetype != "multipart/form-data":
        raise ProvisioningAPIError(
            415,
            "unsupported_media_type",
            "Content-Type måste vara multipart/form-data.",
        )

    headers = {
        name: _single_header(http_request.headers, name)
        for name in REQUIRED_HEADERS
    }
    key_id = headers["X-External-Key-Id"]
    if not KEY_ID_PATTERN.fullmatch(key_id):
        raise ProvisioningAPIError(
            401,
            "unknown_key_id",
            "Angivet key_id är inte aktivt.",
        )

    try:
        keys = load_hmac_keys()
    except ValueError as exc:
        logger.error("Extern HMAC-konfiguration är ogiltig: %s", str(exc))
        raise ProvisioningAPIError(
            500,
            "external_configuration_error",
            "Integrationen är inte korrekt konfigurerad.",
            terminal=False,
        ) from exc
    secret = keys.get(key_id)
    if secret is None:
        raise ProvisioningAPIError(
            401,
            "unknown_key_id",
            "Angivet key_id är inte aktivt.",
        )

    timestamp = headers["X-External-Timestamp"]
    _validate_timestamp(timestamp, _utcnow())
    nonce = headers["X-External-Nonce"]
    if not NONCE_PATTERN.fullmatch(nonce):
        raise ProvisioningAPIError(
            400,
            "invalid_nonce",
            "X-External-Nonce har ett ogiltigt format.",
        )
    idempotency_key = headers["Idempotency-Key"]
    if not IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key):
        raise ProvisioningAPIError(
            400,
            "invalid_idempotency_key",
            "Idempotency-Key har ett ogiltigt format.",
        )
    expected_hash = headers["X-External-Pdf-Sha256"].lower()
    if not SHA256_PATTERN.fullmatch(expected_hash):
        raise ProvisioningAPIError(
            400,
            "invalid_pdf_hash",
            "X-External-Pdf-Sha256 måste vara en SHA-256-hash.",
        )
    supplied_signature = headers["X-External-Signature"]
    if supplied_signature.lower().startswith("sha256="):
        supplied_signature = supplied_signature[7:]
    if not SIGNATURE_PATTERN.fullmatch(supplied_signature):
        raise ProvisioningAPIError(
            401,
            "invalid_signature",
            "Begärans signatur är ogiltig.",
        )

    form_keys = set(http_request.form.keys())
    file_keys = set(http_request.files.keys())
    unknown_fields = (
        form_keys - EXPECTED_FORM_FIELDS
    ) | (file_keys - EXPECTED_FILE_FIELDS)
    misplaced_fields = (form_keys & EXPECTED_FILE_FIELDS) | (
        file_keys & EXPECTED_FORM_FIELDS
    )
    if unknown_fields or misplaced_fields:
        raise ProvisioningAPIError(
            400,
            "unknown_field",
            "Begäran innehåller okända eller felplacerade multipartfält.",
        )
    missing_fields = EXPECTED_FORM_FIELDS - form_keys
    if missing_fields or "pdf" not in file_keys:
        raise ProvisioningAPIError(
            400,
            "missing_field",
            "Alla obligatoriska multipartfält måste anges.",
        )

    raw_fields = {
        field_name: _extract_single_form_value(
            http_request.form,
            field_name,
        )
        for field_name in EXPECTED_FORM_FIELDS
    }
    pdf_values = http_request.files.getlist("pdf")
    if len(pdf_values) != 1:
        raise ProvisioningAPIError(
            400,
            "duplicate_field",
            "Fältet pdf måste anges exakt en gång.",
        )
    file_storage = pdf_values[0]
    if not isinstance(file_storage, FileStorage):
        raise ProvisioningAPIError(
            400,
            "missing_pdf",
            "Fältet pdf måste innehålla en fil.",
        )

    try:
        normalized_pnr = normalize_personnummer(
            raw_fields["personal_identity_number"]
        )
        normalized_email = normalize_email(raw_fields["email"])
    except ValueError as exc:
        raise ProvisioningAPIError(
            400,
            "invalid_business_field",
            str(exc),
        ) from exc
    normalized_name = _normalize_name(raw_fields["name"])
    expires_on, expires_fingerprint = _parse_expiry(
        raw_fields["expires_at"]
    )
    normalized_categories = normalize_category_slugs(
        [raw_fields["category"]]
    )
    if len(normalized_categories) != 1:
        raise ProvisioningAPIError(
            400,
            "invalid_category",
            "Fältet category måste innehålla en giltig kurskategori.",
        )

    request_fingerprint = build_request_fingerprint(
        normalized_pnr,
        normalized_email,
        normalized_name,
        expires_fingerprint,
        normalized_categories[0],
        expected_hash,
    )

    expected_signature = calculate_signature(
        secret,
        key_id=key_id,
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=idempotency_key,
        request_fingerprint=request_fingerprint,
    )
    if not hmac.compare_digest(
        expected_signature,
        supplied_signature.lower(),
    ):
        raise ProvisioningAPIError(
            401,
            "invalid_signature",
            "Begärans signatur är ogiltig.",
        )

    return NormalizedProvisioningRequest(
        key_id=key_id,
        secret=secret,
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=idempotency_key,
        expected_pdf_sha256=expected_hash,
        request_fingerprint=request_fingerprint,
        idempotency_key_hash=_identifier_hash(
            secret,
            "idempotency",
            idempotency_key,
        ),
        nonce_hash=_identifier_hash(secret, "nonce", nonce),
        personal_identity_number=normalized_pnr,
        personnummer_hash=hash_value(normalized_pnr),
        email=normalized_email,
        name=normalized_name,
        expires_on=expires_on,
        expires_at_fingerprint=expires_fingerprint,
        category=normalized_categories[0],
        file_storage=file_storage,
    )


def _register_nonce(command: NormalizedProvisioningRequest) -> None:
    now = _utcnow()
    nonce_ttl = timedelta(hours=DEFAULT_NONCE_TTL_HOURS)
    try:
        with get_engine().begin() as conn:
            conn.execute(
                delete(external_provisioning_nonces_table).where(
                    external_provisioning_nonces_table.c.expires_at <= now
                )
            )
            conn.execute(
                insert(external_provisioning_nonces_table).values(
                    key_id=command.key_id,
                    nonce_hash=command.nonce_hash,
                    expires_at=now + nonce_ttl,
                    created_at=now,
                )
            )
    except IntegrityError as exc:
        raise ProvisioningAPIError(
            409,
            "nonce_reused",
            "Begärans nonce har redan använts.",
        ) from exc


def _insert_request(
    command: NormalizedProvisioningRequest,
) -> RequestClaim | None:
    now = _utcnow()
    try:
        with get_engine().begin() as conn:
            result = conn.execute(
                insert(external_provisioning_requests_table).values(
                    key_id=command.key_id,
                    idempotency_key_hash=command.idempotency_key_hash,
                    request_fingerprint=command.request_fingerprint,
                    state="processing",
                    mail_status="not_started",
                    attempt_count=1,
                    locked_at=now,
                    last_attempt_at=now,
                    personnummer_hash=command.personnummer_hash,
                    pdf_content_sha256=command.expected_pdf_sha256,
                    created_at=now,
                    updated_at=now,
                )
            )
            request_id = int(result.inserted_primary_key[0])
        return RequestClaim(request_id, 1, "initial")
    except IntegrityError:
        return None


def _claim_existing_request(
    command: NormalizedProvisioningRequest,
) -> RequestClaim | ExternalResponse:
    now = _utcnow()
    stale_before = now - _lock_timeout()
    with get_engine().begin() as conn:
        row = conn.execute(
            select(external_provisioning_requests_table).where(
                external_provisioning_requests_table.c.key_id
                == command.key_id,
                external_provisioning_requests_table.c.idempotency_key_hash
                == command.idempotency_key_hash,
            )
        ).first()
        if row is None:
            raise ProvisioningAPIError(
                500,
                "idempotency_state_missing",
                "Integrationsbegäran kunde inte låsas.",
                terminal=False,
            )
        if not hmac.compare_digest(
            row.request_fingerprint,
            command.request_fingerprint,
        ):
            return error_response(
                409,
                "idempotency_key_reused",
                "Idempotency-Key har redan använts för en annan begäran.",
            )
        if row.state in TERMINAL_STATES:
            return _response_from_stored(
                row.http_status,
                row.response_body,
            )
        if row.state == "mail_failed_retryable":
            next_attempt = int(row.attempt_count) + 1
            result = conn.execute(
                update(external_provisioning_requests_table)
                .where(
                    external_provisioning_requests_table.c.id == row.id,
                    external_provisioning_requests_table.c.state
                    == "mail_failed_retryable",
                    external_provisioning_requests_table.c.attempt_count
                    == row.attempt_count,
                )
                .values(
                    state="stored_mail_pending",
                    mail_status="pending",
                    attempt_count=next_attempt,
                    locked_at=now,
                    last_attempt_at=now,
                    http_status=None,
                    response_body=None,
                    updated_at=now,
                )
            )
            if result.rowcount == 1:
                return RequestClaim(
                    int(row.id),
                    next_attempt,
                    "mail_retry",
                )
        elif row.state in {"processing", "stored_mail_pending"}:
            locked_at = _as_utc(row.locked_at)
            if locked_at is not None and locked_at > stale_before:
                return error_response(
                    425,
                    "request_in_progress",
                    "En begäran med samma Idempotency-Key behandlas redan.",
                )
            next_attempt = int(row.attempt_count) + 1
            result = conn.execute(
                update(external_provisioning_requests_table)
                .where(
                    external_provisioning_requests_table.c.id == row.id,
                    external_provisioning_requests_table.c.state
                    == row.state,
                    external_provisioning_requests_table.c.attempt_count
                    == row.attempt_count,
                    or_(
                        external_provisioning_requests_table.c.locked_at.is_(
                            None
                        ),
                        external_provisioning_requests_table.c.locked_at
                        <= stale_before,
                    ),
                )
                .values(
                    attempt_count=next_attempt,
                    locked_at=now,
                    last_attempt_at=now,
                    updated_at=now,
                )
            )
            if result.rowcount == 1:
                mode: ClaimMode = (
                    "initial"
                    if row.state == "processing"
                    and row.mail_status == "not_started"
                    else "mail_retry"
                )
                return RequestClaim(int(row.id), next_attempt, mode)
        elif row.state == "mail_sending":
            locked_at = _as_utc(row.locked_at)
            if locked_at is not None and locked_at > stale_before:
                return error_response(
                    425,
                    "request_in_progress",
                    "E-poststeget för begäran behandlas redan.",
                )
            response = error_response(
                409,
                "delivery_unknown",
                "E-postens leveransläge är okänt. "
                "Manuell eller särskilt kontrollerad hantering krävs.",
            )
            result = conn.execute(
                update(external_provisioning_requests_table)
                .where(
                    external_provisioning_requests_table.c.id == row.id,
                    external_provisioning_requests_table.c.state
                    == "mail_sending",
                    external_provisioning_requests_table.c.attempt_count
                    == row.attempt_count,
                    or_(
                        external_provisioning_requests_table.c.locked_at.is_(
                            None
                        ),
                        external_provisioning_requests_table.c.locked_at
                        <= stale_before,
                    ),
                )
                .values(
                    state="delivery_unknown",
                    mail_status="delivery_unknown",
                    http_status=response.http_status,
                    response_body=response.body_text,
                    locked_at=None,
                    completed_at=now,
                    updated_at=now,
                )
            )
            if result.rowcount == 1:
                return response

    return error_response(
        425,
        "request_in_progress",
        "En begäran med samma Idempotency-Key behandlas redan.",
    )


def _claim_request(
    command: NormalizedProvisioningRequest,
) -> RequestClaim | ExternalResponse:
    inserted = _insert_request(command)
    if inserted is not None:
        return inserted
    return _claim_existing_request(command)


def _read_and_scan_pdf(
    command: NormalizedProvisioningRequest,
) -> bytes:
    file_storage = command.file_storage
    filename = (file_storage.filename or "").strip()
    if not filename or not filename.lower().endswith(".pdf"):
        raise ProvisioningAPIError(
            415,
            "unsupported_pdf_filename",
            "PDF-filen måste ha filändelsen .pdf.",
        )
    if (file_storage.mimetype or "").strip().lower() != "application/pdf":
        raise ProvisioningAPIError(
            415,
            "unsupported_pdf_mime",
            "PDF-filen måste ha MIME-typen application/pdf.",
        )

    max_bytes = _external_pdf_max_bytes()
    stream = file_storage.stream
    stream.seek(0)
    content = stream.read(max_bytes + 1)
    stream.seek(0)
    if len(content) > max_bytes:
        raise ProvisioningAPIError(
            413,
            "pdf_too_large",
            "PDF-filen överskrider integrationens storleksgräns.",
        )
    if not content.startswith(b"%PDF-"):
        raise ProvisioningAPIError(
            415,
            "invalid_pdf",
            "Filen innehåller inte en giltig PDF-signatur.",
        )
    actual_hash = hashlib.sha256(content).hexdigest()
    if not hmac.compare_digest(
        actual_hash,
        command.expected_pdf_sha256,
    ):
        raise ProvisioningAPIError(
            400,
            "pdf_hash_mismatch",
            "PDF-innehållet matchar inte X-External-Pdf-Sha256.",
        )

    try:
        verdict: ScanVerdict = scan_pdf_bytes(content, logger)
    except PDFScannerTimeoutError as exc:
        raise ProvisioningAPIError(
            500,
            "pdf_scanner_timeout",
            "PDF-filen kunde inte säkerhetsskannas i tid.",
            terminal=False,
        ) from exc
    except PDFScannerUnavailableError as exc:
        raise ProvisioningAPIError(
            500,
            "pdf_scanner_unavailable",
            "PDF-säkerhetsskannern är tillfälligt otillgänglig.",
            terminal=False,
        ) from exc
    except PDFScannerExecutionError as exc:
        raise ProvisioningAPIError(
            500,
            "pdf_scanner_error",
            "PDF-säkerhetsskannern rapporterade ett fel.",
            terminal=False,
        ) from exc
    if verdict.decision != "ALLOW":
        raise ProvisioningAPIError(
            400,
            "pdf_rejected",
            "PDF-filen avvisades av säkerhetsskannern.",
        )
    return content


def _advisory_identity_locks(
    conn: Connection,
    identities: list[str],
) -> None:
    acquire_private_provisioning_identity_locks(conn, identities)


def _account_is_company_connected(
    conn: Connection,
    personnummer_hash: str,
    orgnr_normalized: str | None,
) -> bool:
    if (orgnr_normalized or "").strip():
        return True
    connection = conn.execute(
        select(supervisor_connections_table.c.id)
        .where(
            supervisor_connections_table.c.user_personnummer
            == personnummer_hash
        )
        .limit(1)
    ).scalar_one_or_none()
    return connection is not None


def _email_conflict_exists(
    conn: Connection,
    email: str,
    *,
    exclude_personnummer_hash: str | None = None,
) -> bool:
    email_values = email_lookup_values(email)
    active_query = select(users_table.c.id).where(
        users_table.c.email.in_(email_values)
    )
    pending_query = select(pending_users_table.c.id).where(
        pending_users_table.c.email.in_(email_values)
    )
    if exclude_personnummer_hash:
        active_query = active_query.where(
            users_table.c.personnummer != exclude_personnummer_hash
        )
        pending_query = pending_query.where(
            pending_users_table.c.personnummer
            != exclude_personnummer_hash
        )
    if conn.execute(active_query.limit(1)).scalar_one_or_none() is not None:
        return True
    if conn.execute(pending_query.limit(1)).scalar_one_or_none() is not None:
        return True
    return False


def _forbidden_email_account_exists(
    conn: Connection,
    email: str,
) -> bool:
    email_values = email_lookup_values(email)
    queries = (
        select(supervisors_table.c.id).where(
            supervisors_table.c.email.in_(email_values)
        ),
        select(pending_supervisors_table.c.id).where(
            pending_supervisors_table.c.email.in_(email_values)
        ),
        select(company_users_table.c.id).where(
            company_users_table.c.role == "foretagskonto",
            company_users_table.c.email.in_(email_values),
        ),
    )
    return any(
        conn.execute(query.limit(1)).scalar_one_or_none() is not None
        for query in queries
    )


def _stored_active_email(
    stored_email: str,
    incoming_email: str,
) -> str | None:
    stored_value = (stored_email or "").strip().lower()
    if "@" in stored_value:
        try:
            return normalize_email(stored_value)
        except ValueError:
            return None
    if _is_valid_hash(stored_value):
        _normalized, incoming_legacy_hash = email_lookup_values(
            incoming_email
        )
        if hmac.compare_digest(stored_value, incoming_legacy_hash):
            return incoming_email
    return None


def _resolve_account(
    conn: Connection,
    command: NormalizedProvisioningRequest,
) -> AccountResolution:
    active_query = select(
        users_table.c.username,
        users_table.c.email,
        users_table.c.personnummer,
        users_table.c.orgnr_normalized,
    ).where(
        users_table.c.personnummer == command.personnummer_hash
    )
    pending_query = select(
        pending_users_table.c.username,
        pending_users_table.c.email,
        pending_users_table.c.personnummer,
        pending_users_table.c.orgnr_normalized,
    ).where(
        pending_users_table.c.personnummer == command.personnummer_hash
    )
    if conn.dialect.name.startswith("postgresql"):
        active_query = active_query.with_for_update()
        pending_query = pending_query.with_for_update()
    active = conn.execute(active_query).first()
    pending = conn.execute(pending_query).first()
    if active is not None and pending is not None:
        raise ProvisioningAPIError(
            409,
            "account_state_conflict",
            "Personnumret finns både som aktivt och väntande konto.",
        )

    if active is not None:
        if _account_is_company_connected(
            conn,
            command.personnummer_hash,
            active.orgnr_normalized,
        ):
            raise ProvisioningAPIError(
                409,
                "account_type_not_allowed",
                "Ett företagskopplat privatkonto kan inte provisioneras.",
            )
        return AccountResolution(
            state="active",
            personnummer_hash=command.personnummer_hash,
            recipient_email=_stored_active_email(
                active.email,
                command.email,
            ),
            recipient_name=active.username,
            activation_required=False,
        )

    if pending is not None:
        if _account_is_company_connected(
            conn,
            command.personnummer_hash,
            pending.orgnr_normalized,
        ):
            raise ProvisioningAPIError(
                409,
                "account_type_not_allowed",
                "Ett företagskopplat privatkonto kan inte provisioneras.",
            )
        if _forbidden_email_account_exists(conn, command.email):
            raise ProvisioningAPIError(
                409,
                "account_type_not_allowed",
                "E-postadressen tillhör en kontotyp som inte stöds.",
            )
        if _email_conflict_exists(
            conn,
            command.email,
            exclude_personnummer_hash=command.personnummer_hash,
        ):
            raise ProvisioningAPIError(
                409,
                "email_conflict",
                "E-postadressen används redan av ett annat privatkonto.",
            )
        update_result = conn.execute(
            update(pending_users_table)
            .where(
                pending_users_table.c.personnummer
                == command.personnummer_hash
            )
            .values(
                username=command.name,
                email=command.email,
            )
        )
        if update_result.rowcount != 1:
            raise ProvisioningAPIError(
                409,
                "pending_account_missing",
                "Det väntande privatkontot finns inte längre.",
            )
        return AccountResolution(
            state="pending",
            personnummer_hash=command.personnummer_hash,
            recipient_email=command.email,
            recipient_name=command.name,
            activation_required=True,
        )

    if _forbidden_email_account_exists(conn, command.email):
        raise ProvisioningAPIError(
            409,
            "account_type_not_allowed",
            "E-postadressen tillhör en kontotyp som inte stöds.",
        )
    if _email_conflict_exists(conn, command.email):
        raise ProvisioningAPIError(
            409,
            "email_conflict",
            "E-postadressen används redan av ett annat privatkonto.",
        )
    conn.execute(
        insert(pending_users_table).values(
            username=command.name,
            email=command.email,
            personnummer=command.personnummer_hash,
            orgnr_normalized="",
        )
    )
    return AccountResolution(
        state="pending",
        personnummer_hash=command.personnummer_hash,
        recipient_email=command.email,
        recipient_name=command.name,
        activation_required=True,
    )


def _build_stored_filename(
    _original_filename: str,
    _normalized_pnr: str,
    now: datetime,
) -> str:
    # Originalfilnamn är klientstyrda och kan innehålla personnummer eller
    # andra känsliga uppgifter. Lagra därför ett helt serverstyrt namn.
    return f"{int(now.timestamp())}_intyg.pdf"


def _create_activation_token(
    conn: Connection,
    *,
    request_id: int,
    personnummer_hash: str,
    now: datetime,
) -> str:
    conn.execute(
        update(private_account_activation_tokens_table)
        .where(
            private_account_activation_tokens_table.c.pending_user_personnummer
            == personnummer_hash,
            private_account_activation_tokens_table.c.used_at.is_(None),
            private_account_activation_tokens_table.c.revoked_at.is_(None),
            private_account_activation_tokens_table.c.superseded_at.is_(
                None
            ),
        )
        .values(superseded_at=now)
    )
    for _attempt in range(5):
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        try:
            with conn.begin_nested():
                conn.execute(
                    insert(private_account_activation_tokens_table).values(
                        pending_user_personnummer=personnummer_hash,
                        provisioning_request_id=request_id,
                        token_hash=token_hash,
                        created_at=now,
                        expires_at=now + _activation_ttl(),
                    )
                )
            return raw_token
        except IntegrityError:
            continue
    raise RuntimeError("Kunde inte skapa en unik aktiveringstoken.")


def _insert_pdf(
    conn: Connection,
    command: NormalizedProvisioningRequest,
    content: bytes,
    filename: str,
    now: datetime,
) -> int:
    try:
        with conn.begin_nested():
            result = conn.execute(
                insert(user_pdfs_table).values(
                    personnummer=command.personnummer_hash,
                    filename=filename,
                    content=content,
                    content_sha256=command.expected_pdf_sha256,
                    categories=command.category,
                    note="",
                    expires_on=command.expires_on,
                    uploaded_at=now,
                )
            )
        return int(result.inserted_primary_key[0])
    except IntegrityError as exc:
        existing_id = conn.execute(
            select(user_pdfs_table.c.id).where(
                user_pdfs_table.c.personnummer
                == command.personnummer_hash,
                user_pdfs_table.c.content_sha256
                == command.expected_pdf_sha256,
            )
        ).scalar_one_or_none()
        if existing_id is not None:
            raise ProvisioningAPIError(
                409,
                "document_already_exists",
                "Samma PDF-dokument finns redan för privatkontot.",
            ) from exc
        raise


def _ensure_request_lease(
    conn: Connection,
    claim: RequestClaim,
    expected_state: str,
) -> None:
    query = select(external_provisioning_requests_table.c.id).where(
        external_provisioning_requests_table.c.id == claim.request_id,
        external_provisioning_requests_table.c.state == expected_state,
        external_provisioning_requests_table.c.attempt_count
        == claim.attempt_count,
    )
    if conn.dialect.name.startswith("postgresql"):
        query = query.with_for_update()
    if conn.execute(query).scalar_one_or_none() is None:
        raise RequestLeaseLostError(
            "Integrationsbegärans lease har tagits över."
        )


def _store_initial_provisioning(
    command: NormalizedProvisioningRequest,
    claim: RequestClaim,
    content: bytes,
) -> MailContext | ExternalResponse:
    now = _utcnow()
    filename = _build_stored_filename(
        command.file_storage.filename or "intyg.pdf",
        command.personal_identity_number,
        now,
    )
    try:
        with get_engine().begin() as conn:
            _ensure_request_lease(conn, claim, "processing")
            email_hash = hash_value(command.email)
            _advisory_identity_locks(
                conn,
                [
                    f"pnr:{command.personnummer_hash}",
                    f"email:{email_hash}",
                ],
            )
            account = _resolve_account(conn, command)
            pdf_id = _insert_pdf(
                conn,
                command,
                content,
                filename,
                now,
            )
            activation_token = None
            if account.activation_required:
                activation_token = _create_activation_token(
                    conn,
                    request_id=claim.request_id,
                    personnummer_hash=command.personnummer_hash,
                    now=now,
                )

            if account.recipient_email is None:
                response = success_response(
                    "provisioning_completed",
                    "Privatkontot och PDF-dokumentet har behandlats.",
                    account_state=account.state,
                    mail_status="not_required",
                )
                result = conn.execute(
                    update(external_provisioning_requests_table)
                    .where(
                        external_provisioning_requests_table.c.id
                        == claim.request_id,
                        external_provisioning_requests_table.c.state
                        == "processing",
                        external_provisioning_requests_table.c.attempt_count
                        == claim.attempt_count,
                    )
                    .values(
                        state="completed",
                        mail_status="not_required",
                        http_status=response.http_status,
                        response_body=response.body_text,
                        pdf_id=pdf_id,
                        account_state=account.state,
                        locked_at=None,
                        completed_at=now,
                        updated_at=now,
                    )
                )
                if result.rowcount != 1:
                    raise RequestLeaseLostError(
                        "Integrationsbegärans lease har tagits över."
                    )
                return response

            result = conn.execute(
                update(external_provisioning_requests_table)
                .where(
                    external_provisioning_requests_table.c.id
                    == claim.request_id,
                    external_provisioning_requests_table.c.state
                    == "processing",
                    external_provisioning_requests_table.c.attempt_count
                    == claim.attempt_count,
                )
                .values(
                    state="stored_mail_pending",
                    mail_status="pending",
                    pdf_id=pdf_id,
                    account_state=account.state,
                    locked_at=now,
                    updated_at=now,
                )
            )
            if result.rowcount != 1:
                raise RequestLeaseLostError(
                    "Integrationsbegärans lease har tagits över."
                )

        return MailContext(
            request_id=claim.request_id,
            attempt_count=claim.attempt_count,
            idempotency_key_hash=command.idempotency_key_hash,
            account_state=account.state,
            recipient_email=account.recipient_email,
            recipient_name=account.recipient_name,
            filename=filename,
            pdf_content=content,
            activation_token=activation_token,
        )
    except OperationalError as exc:
        raise ProvisioningAPIError(
            500,
            "database_temporarily_unavailable",
            "Databasen kunde inte slutföra integrationsbegäran.",
            terminal=False,
        ) from exc


def _load_mail_retry_context(
    command: NormalizedProvisioningRequest,
    claim: RequestClaim,
) -> MailContext:
    now = _utcnow()
    with get_engine().begin() as conn:
        _ensure_request_lease(conn, claim, "stored_mail_pending")
        _advisory_identity_locks(
            conn,
            [f"pnr:{command.personnummer_hash}"],
        )
        request_row = conn.execute(
            select(
                external_provisioning_requests_table.c.pdf_id,
                external_provisioning_requests_table.c.account_state,
            ).where(
                external_provisioning_requests_table.c.id
                == claim.request_id
            )
        ).first()
        if request_row is None or request_row.pdf_id is None:
            raise ProvisioningAPIError(
                500,
                "stored_document_missing",
                "Det lagrade PDF-dokumentet kunde inte hittas.",
            )
        pdf_row = conn.execute(
            select(
                user_pdfs_table.c.filename,
                user_pdfs_table.c.content,
            ).where(
                user_pdfs_table.c.id == request_row.pdf_id,
                user_pdfs_table.c.personnummer
                == command.personnummer_hash,
                user_pdfs_table.c.content_sha256
                == command.expected_pdf_sha256,
            )
        ).first()
        if pdf_row is None:
            raise ProvisioningAPIError(
                500,
                "stored_document_missing",
                "Det lagrade PDF-dokumentet kunde inte hittas.",
            )

        activation_token = None
        if request_row.account_state == "pending":
            account_row = conn.execute(
                select(
                    pending_users_table.c.username,
                    pending_users_table.c.email,
                ).where(
                    pending_users_table.c.personnummer
                    == command.personnummer_hash
                )
            ).first()
            if account_row is None:
                raise ProvisioningAPIError(
                    409,
                    "pending_account_missing",
                    "Det väntande privatkontot finns inte längre.",
                )
            recipient_email = normalize_email(account_row.email)
            recipient_name = account_row.username
            activation_token = _create_activation_token(
                conn,
                request_id=claim.request_id,
                personnummer_hash=command.personnummer_hash,
                now=now,
            )
        else:
            account_row = conn.execute(
                select(
                    users_table.c.username,
                    users_table.c.email,
                ).where(
                    users_table.c.personnummer
                    == command.personnummer_hash
                )
            ).first()
            if account_row is None:
                raise ProvisioningAPIError(
                    409,
                    "active_account_missing",
                    "Det aktiva privatkontot finns inte längre.",
                )
            recipient_email = _stored_active_email(
                account_row.email,
                command.email,
            )
            if recipient_email is None:
                raise ProvisioningAPIError(
                    409,
                    "active_email_unavailable",
                    "Det aktiva kontots e-postadress kan inte användas säkert.",
                )
            recipient_name = account_row.username

        return MailContext(
            request_id=claim.request_id,
            attempt_count=claim.attempt_count,
            idempotency_key_hash=command.idempotency_key_hash,
            account_state=str(request_row.account_state),
            recipient_email=recipient_email,
            recipient_name=recipient_name,
            filename=pdf_row.filename,
            pdf_content=bytes(pdf_row.content),
            activation_token=activation_token,
        )


def _begin_mail_sending(context: MailContext) -> None:
    now = _utcnow()
    with get_engine().begin() as conn:
        result = conn.execute(
            update(external_provisioning_requests_table)
            .where(
                external_provisioning_requests_table.c.id
                == context.request_id,
                external_provisioning_requests_table.c.state
                == "stored_mail_pending",
                external_provisioning_requests_table.c.attempt_count
                == context.attempt_count,
            )
            .values(
                state="mail_sending",
                mail_status="sending",
                locked_at=now,
                last_attempt_at=now,
                updated_at=now,
            )
        )
        if result.rowcount != 1:
            raise RequestLeaseLostError(
                "Integrationsbegärans mail-lease har tagits över."
            )


def _message_id(context: MailContext) -> str:
    base_url = (os.getenv("BASE_URL") or "").strip()
    parsed = urlparse(base_url)
    domain = parsed.hostname or "utbildningsintyg.se"
    if not re.fullmatch(r"[A-Za-z0-9.-]+", domain):
        domain = "utbildningsintyg.se"
    # Alla försök för samma idempotenta begäran delar logisk Message-ID.
    identity = context.idempotency_key_hash[:48]
    return f"<external-{identity}@{domain}>"


def _finish_mail_success(context: MailContext) -> ExternalResponse:
    response = success_response(
        "provisioning_completed",
        "Privatkontot och PDF-dokumentet har behandlats.",
        account_state=context.account_state,
        mail_status="sent",
    )
    now = _utcnow()
    with get_engine().begin() as conn:
        result = conn.execute(
            update(external_provisioning_requests_table)
            .where(
                external_provisioning_requests_table.c.id
                == context.request_id,
                external_provisioning_requests_table.c.state
                == "mail_sending",
                external_provisioning_requests_table.c.attempt_count
                == context.attempt_count,
            )
            .values(
                state="completed",
                mail_status="sent",
                http_status=response.http_status,
                response_body=response.body_text,
                locked_at=None,
                completed_at=now,
                updated_at=now,
            )
        )
        if result.rowcount != 1:
            raise RequestLeaseLostError(
                "Integrationsbegärans mail-lease har tagits över."
            )
    return response


def _finish_mail_failure(
    context: MailContext,
    *,
    delivery_unknown: bool,
    code: str,
    message: str,
) -> ExternalResponse:
    response = error_response(
        409 if delivery_unknown else 500,
        code,
        message,
    )
    now = _utcnow()
    state = "delivery_unknown" if delivery_unknown else "mail_failed_retryable"
    mail_status = (
        "delivery_unknown" if delivery_unknown else "failed_retryable"
    )
    with get_engine().begin() as conn:
        result = conn.execute(
            update(external_provisioning_requests_table)
            .where(
                external_provisioning_requests_table.c.id
                == context.request_id,
                external_provisioning_requests_table.c.state
                == "mail_sending",
                external_provisioning_requests_table.c.attempt_count
                == context.attempt_count,
            )
            .values(
                state=state,
                mail_status=mail_status,
                http_status=response.http_status,
                response_body=response.body_text,
                locked_at=None,
                completed_at=now if delivery_unknown else None,
                updated_at=now,
            )
        )
        if result.rowcount != 1:
            raise RequestLeaseLostError(
                "Integrationsbegärans mail-lease har tagits över."
            )
    return response


def _send_mail(
    context: MailContext,
    activation_url_builder: Callable[[str], str],
) -> ExternalResponse:
    _begin_mail_sending(context)
    send_started = False
    try:
        activation_link = (
            activation_url_builder(context.activation_token)
            if context.activation_token
            else None
        )
        send_started = True
        email_service.send_external_private_provisioning_email(
            context.recipient_email,
            context.recipient_name,
            context.filename,
            context.pdf_content,
            _message_id(context),
            activation_link=activation_link,
        )
    except email_service.EmailDeliveryUnknownError:
        logger.error(
            "Extern provisioning fick okänt leveransläge för request %s",
            context.request_id,
        )
        return _finish_mail_failure(
            context,
            delivery_unknown=True,
            code="delivery_unknown",
            message=(
                "E-postens leveransläge är okänt. "
                "Manuell eller särskilt kontrollerad hantering krävs."
            ),
        )
    except email_service.EmailNotSentError:
        logger.warning(
            "Extern provisioning kunde inte skicka mejl för request %s",
            context.request_id,
        )
        return _finish_mail_failure(
            context,
            delivery_unknown=False,
            code="mail_delivery_failed",
            message=(
                "Kontot och PDF-dokumentet har lagrats, men e-postutskicket "
                "misslyckades och kan försöka igen."
            ),
        )
    except Exception as exc:
        logger.error(
            "Extern provisioning fick oväntat mailfel för request %s "
            "(felklass=%s)",
            context.request_id,
            type(exc).__name__,
        )
        return _finish_mail_failure(
            context,
            delivery_unknown=send_started,
            code=(
                "delivery_unknown"
                if send_started
                else "mail_delivery_failed"
            ),
            message=(
                (
                    "E-postens leveransläge är okänt. Manuell eller "
                    "särskilt kontrollerad hantering krävs."
                )
                if send_started
                else (
                    "Kontot och PDF-dokumentet har lagrats, men "
                    "e-postutskicket kunde inte förberedas och kan "
                    "försökas igen."
                )
            ),
        )
    return _finish_mail_success(context)


def _persist_processing_error(
    claim: RequestClaim,
    error: ProvisioningAPIError,
) -> ExternalResponse:
    response = error_response(
        error.http_status,
        error.code,
        error.message,
    )
    now = _utcnow()
    target_state = "failed_terminal" if error.terminal else "processing"
    values: dict[str, Any] = {
        "state": target_state,
        "http_status": response.http_status,
        "response_body": response.body_text,
        "locked_at": None,
        "updated_at": now,
    }
    if error.terminal:
        values["completed_at"] = now
    with get_engine().begin() as conn:
        result = conn.execute(
            update(external_provisioning_requests_table)
            .where(
                external_provisioning_requests_table.c.id
                == claim.request_id,
                external_provisioning_requests_table.c.attempt_count
                == claim.attempt_count,
                external_provisioning_requests_table.c.state.in_(
                    ("processing", "stored_mail_pending")
                ),
            )
            .values(**values)
        )
        if result.rowcount != 1:
            return error_response(
                425,
                "request_in_progress",
                "Integrationsbegäran har tagits över av en annan worker.",
            )
    return response


def handle_provisioning_request(
    http_request: Any,
    *,
    activation_url_builder: Callable[[str], str],
) -> ExternalResponse:
    result: ExternalResponse | None = None

    def capture(response: ExternalResponse) -> ExternalResponse:
        nonlocal result
        result = response
        return response

    if not external_provisioning_enabled():
        return capture(
            error_response(
                404,
                "external_route_not_found",
                "Den externa API-rutten är inte aktiverad.",
            )
        )
    try:
        command = _normalize_http_request(http_request)
        _register_nonce(command)
        claim_or_response = _claim_request(command)
        if isinstance(claim_or_response, ExternalResponse):
            return capture(claim_or_response)
        claim = claim_or_response

        if claim.mode == "mail_retry":
            context = _load_mail_retry_context(command, claim)
            return capture(_send_mail(context, activation_url_builder))

        content = _read_and_scan_pdf(command)
        stored = _store_initial_provisioning(
            command,
            claim,
            content,
        )
        if isinstance(stored, ExternalResponse):
            return capture(stored)
        return capture(_send_mail(stored, activation_url_builder))
    except ProvisioningAPIError as exc:
        if "claim" in locals():
            return capture(_persist_processing_error(claim, exc))
        return capture(
            error_response(exc.http_status, exc.code, exc.message)
        )
    except RequestLeaseLostError:
        return capture(
            error_response(
                425,
                "request_in_progress",
                "Integrationsbegäran har tagits över av en annan worker.",
            )
        )
    except RequestEntityTooLarge:
        # Flask's handler owns the documented JSON/no-store response for the
        # global request-size limit.
        raise
    except IntegrityError as exc:
        logger.error(
            "Databasconstraint stoppade extern provisioning "
            "(felklass=%s)",
            type(exc).__name__,
        )
        if "claim" in locals():
            error = ProvisioningAPIError(
                409,
                "provisioning_conflict",
                "Integrationsbegäran står i konflikt med befintliga data.",
            )
            return capture(_persist_processing_error(claim, error))
        return capture(
            error_response(
                409,
                "provisioning_conflict",
                "Integrationsbegäran står i konflikt med befintliga data.",
            )
        )
    except Exception as exc:
        logger.error(
            "Oväntat fel i external private provisioning (felklass=%s)",
            type(exc).__name__,
        )
        if "claim" in locals():
            error = ProvisioningAPIError(
                500,
                "internal_error",
                "Ett internt fel uppstod vid behandling av integrationsbegäran.",
                terminal=False,
            )
            return capture(_persist_processing_error(claim, error))
        return capture(
            error_response(
                500,
                "internal_error",
                "Ett internt fel uppstod vid behandling av integrationsbegäran.",
            )
        )
    finally:
        if "command" in locals():
            request_state = "not_persisted"
            try:
                with get_engine().connect() as conn:
                    stored_state = conn.execute(
                        select(
                            external_provisioning_requests_table.c.state
                        ).where(
                            external_provisioning_requests_table.c.key_id
                            == command.key_id,
                            external_provisioning_requests_table.c
                            .idempotency_key_hash
                            == command.idempotency_key_hash,
                        )
                    ).scalar_one_or_none()
                if stored_state:
                    request_state = str(stored_state)
            except Exception as exc:
                logger.warning(
                    "Kunde inte läsa request-state för extern provisioning "
                    "(felklass=%s)",
                    type(exc).__name__,
                )
            logger.info(
                "External provisioning: key_id=%s nonce=%s idempotency=%s "
                "personnummer=%s email=%s pdf=%s request_state=%s "
                "result_code=%s route=%s",
                command.key_id,
                mask_hash(command.nonce_hash),
                mask_hash(command.idempotency_key_hash),
                mask_hash(command.personnummer_hash),
                mask_hash(hash_value(command.email)),
                mask_hash(command.expected_pdf_sha256),
                request_state,
                result.body.get("code", "unhandled_exception")
                if result is not None
                else "unhandled_exception",
                EXTERNAL_ROUTE,
            )


def _activation_token_hash(raw_token: str) -> str:
    if not raw_token or len(raw_token) > 512:
        return ""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def get_activation_token_status(
    *,
    token: str | None = None,
    token_hash: str | None = None,
) -> ActivationTokenStatus:
    resolved_hash = token_hash or _activation_token_hash(token or "")
    if not SHA256_PATTERN.fullmatch(resolved_hash):
        return ActivationTokenStatus(False)
    now = _utcnow()
    with get_engine().connect() as conn:
        row = conn.execute(
            select(
                private_account_activation_tokens_table.c.token_hash
            ).where(
                private_account_activation_tokens_table.c.token_hash
                == resolved_hash,
                private_account_activation_tokens_table.c.used_at.is_(None),
                private_account_activation_tokens_table.c.revoked_at.is_(
                    None
                ),
                private_account_activation_tokens_table.c.superseded_at.is_(
                    None
                ),
                private_account_activation_tokens_table.c.expires_at > now,
            )
        ).first()
    return ActivationTokenStatus(
        row is not None,
        resolved_hash if row is not None else None,
    )


def pending_account_requires_activation_token(
    personnummer_hash: str,
) -> bool:
    if not _is_valid_hash(personnummer_hash):
        return False
    with get_engine().connect() as conn:
        token_id = conn.execute(
            select(private_account_activation_tokens_table.c.id)
            .where(
                private_account_activation_tokens_table.c.pending_user_personnummer
                == personnummer_hash
            )
            .limit(1)
        ).scalar_one_or_none()
    return token_id is not None


def activate_private_account(
    password: str,
    *,
    token: str | None = None,
    token_hash: str | None = None,
) -> bool:
    resolved_hash = token_hash or _activation_token_hash(token or "")
    if not SHA256_PATTERN.fullmatch(resolved_hash):
        return False
    if not get_activation_token_status(token_hash=resolved_hash).valid:
        return False
    now = _utcnow()
    password_digest = hash_password(password)
    try:
        with get_engine().begin() as conn:
            token_row = conn.execute(
                select(
                    private_account_activation_tokens_table.c.id,
                    private_account_activation_tokens_table.c.pending_user_personnummer,
                ).where(
                    private_account_activation_tokens_table.c.token_hash
                    == resolved_hash
                )
            ).first()
            if token_row is None:
                return False
            _advisory_identity_locks(
                conn,
                [f"pnr:{token_row.pending_user_personnummer}"],
            )
            claim_result = conn.execute(
                update(private_account_activation_tokens_table)
                .where(
                    private_account_activation_tokens_table.c.id
                    == token_row.id,
                    private_account_activation_tokens_table.c.used_at.is_(
                        None
                    ),
                    private_account_activation_tokens_table.c.revoked_at.is_(
                        None
                    ),
                    private_account_activation_tokens_table.c.superseded_at.is_(
                        None
                    ),
                    private_account_activation_tokens_table.c.expires_at
                    > now,
                )
                .values(used_at=now)
            )
            if claim_result.rowcount != 1:
                return False

            pending = conn.execute(
                select(
                    pending_users_table.c.username,
                    pending_users_table.c.email,
                    pending_users_table.c.personnummer,
                    pending_users_table.c.orgnr_normalized,
                ).where(
                    pending_users_table.c.personnummer
                    == token_row.pending_user_personnummer
                )
            ).first()
            if pending is None:
                raise RequestLeaseLostError(
                    "Väntande konto saknas för aktiveringstoken."
                )
            active = conn.execute(
                select(users_table.c.id).where(
                    users_table.c.personnummer == pending.personnummer
                )
            ).scalar_one_or_none()
            if active is not None:
                raise RequestLeaseLostError(
                    "Kontot är redan aktiverat."
                )

            conn.execute(
                delete(pending_users_table).where(
                    pending_users_table.c.personnummer
                    == pending.personnummer
                )
            )
            conn.execute(
                insert(users_table).values(
                    username=pending.username,
                    email=pending.email,
                    password=password_digest,
                    personnummer=pending.personnummer,
                    orgnr_normalized=pending.orgnr_normalized or "",
                )
            )
            conn.execute(
                update(private_account_activation_tokens_table)
                .where(
                    private_account_activation_tokens_table.c.pending_user_personnummer
                    == pending.personnummer,
                    private_account_activation_tokens_table.c.id
                    != token_row.id,
                    private_account_activation_tokens_table.c.used_at.is_(
                        None
                    ),
                    private_account_activation_tokens_table.c.revoked_at.is_(
                        None
                    ),
                )
                .values(revoked_at=now)
            )
        return True
    except (IntegrityError, OperationalError, RequestLeaseLostError):
        return False


# Copyright (c) Liam Suorsa and Mika Suorsa
