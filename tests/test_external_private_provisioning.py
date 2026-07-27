from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import BytesIO
from threading import Barrier, Lock
from time import time
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from werkzeug.datastructures import MultiDict

import app
import functions
from course_categories import COURSE_CATEGORIES
from services import external_private_provisioning as provisioning


ROUTE = "/api/external/private-account-provisioning"
KEY_ID = "test-partner"
HMAC_SECRET = "test-external-hmac-secret-that-is-at-least-32-bytes"
PERSONNUMMER = "9001011234"
EMAIL = "anna@example.com"
NAME = "Anna Andersson"
CATEGORY = COURSE_CATEGORIES[0][0]
PDF_CONTENT = (
    b"%PDF-1.4\n"
    b"1 0 obj\n"
    b"<< /Type /Catalog >>\n"
    b"endobj\n"
    b"trailer\n"
    b"<<>>\n"
    b"%%EOF\n"
)


class SimulatedWorkerCrash(BaseException):
    pass


@dataclass
class ExternalAPIHarness:
    client: Any
    mail_calls: list[dict[str, Any]]
    mail_outcomes: list[BaseException | None]
    scan_calls: list[bytes]
    scan_outcomes: list[BaseException | provisioning.ScanVerdict]

    def post(
        self,
        *,
        idempotency_key: str | None = None,
        nonce: str | None = None,
        pdf_content: bytes = PDF_CONTENT,
        declared_pdf_sha256: str | None = None,
        mime_type: str = "application/pdf",
        filename: str = "utbildningsintyg.pdf",
        fields: dict[str, str] | None = None,
        timestamp: str | None = None,
        key_id: str = KEY_ID,
        hmac_secret: str = HMAC_SECRET,
        signature_override: str | None = None,
        additional_form_fields: list[tuple[str, Any]] | None = None,
        client: Any | None = None,
    ):
        form_fields = {
            "personal_identity_number": PERSONNUMMER,
            "email": EMAIL,
            "name": NAME,
            "expires_at": "2030-12-31",
            "category": CATEGORY,
        }
        form_fields.update(fields or {})
        pdf_hash = declared_pdf_sha256 or sha256(pdf_content).hexdigest()
        request_timestamp = timestamp or str(int(time()))
        request_nonce = nonce or f"nonce-{uuid4().hex}"
        request_idempotency_key = (
            idempotency_key or f"idempotency-{uuid4().hex}"
        )
        fingerprint = provisioning.build_request_fingerprint(
            form_fields["personal_identity_number"],
            form_fields["email"],
            form_fields["name"],
            form_fields["expires_at"],
            form_fields["category"],
            pdf_hash,
        )
        signature = provisioning.calculate_signature(
            hmac_secret,
            key_id=key_id,
            timestamp=request_timestamp,
            nonce=request_nonce,
            idempotency_key=request_idempotency_key,
            request_fingerprint=fingerprint,
        )
        headers = {
            "X-External-Key-Id": key_id,
            "X-External-Timestamp": request_timestamp,
            "X-External-Nonce": request_nonce,
            "Idempotency-Key": request_idempotency_key,
            "X-External-Pdf-Sha256": pdf_hash,
            "X-External-Signature": signature_override or signature,
        }
        data = MultiDict(form_fields.items())
        data.add("pdf", (BytesIO(pdf_content), filename, mime_type))
        for field_name, value in additional_form_fields or []:
            data.add(field_name, value)
        request_client = client or self.client
        return request_client.post(ROUTE, data=data, headers=headers)


@pytest.fixture
def external_api(_empty_db, monkeypatch) -> ExternalAPIHarness:
    monkeypatch.setenv("EXTERNAL_PRIVATE_PROVISIONING_ENABLED", "true")
    monkeypatch.setenv(
        "EXTERNAL_PROVISIONING_HMAC_KEYS",
        f'{{"{KEY_ID}":"{HMAC_SECRET}"}}',
    )
    monkeypatch.setenv("BASE_URL", "https://intyg.example")
    monkeypatch.setitem(app.app.config, "TESTING", True)

    mail_calls: list[dict[str, Any]] = []
    mail_outcomes: list[BaseException | None] = []
    scan_calls: list[bytes] = []
    scan_outcomes: list[BaseException | provisioning.ScanVerdict] = []

    def scan_pdf(content: bytes, _logger=None):
        scan_calls.append(content)
        if scan_outcomes:
            outcome = scan_outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        return provisioning.ScanVerdict("ALLOW", [])

    def send_mail(
        to_email: str,
        recipient_name: str,
        filename: str,
        pdf_content: bytes,
        message_id: str,
        *,
        activation_link: str | None = None,
    ) -> None:
        mail_calls.append(
            {
                "to_email": to_email,
                "recipient_name": recipient_name,
                "filename": filename,
                "pdf_content": pdf_content,
                "message_id": message_id,
                "activation_link": activation_link,
            }
        )
        if mail_outcomes:
            outcome = mail_outcomes.pop(0)
            if outcome is not None:
                raise outcome

    monkeypatch.setattr(provisioning, "scan_pdf_bytes", scan_pdf)
    monkeypatch.setattr(
        provisioning.email_service,
        "send_external_private_provisioning_email",
        send_mail,
    )
    return ExternalAPIHarness(
        client=app.app.test_client(),
        mail_calls=mail_calls,
        mail_outcomes=mail_outcomes,
        scan_calls=scan_calls,
        scan_outcomes=scan_outcomes,
    )


def _count_rows(table) -> int:
    with functions.get_engine().connect() as conn:
        return int(
            conn.execute(
                select(func.count()).select_from(table)
            ).scalar_one()
        )


def _assert_json_response(response, status_code: int, code: str) -> None:
    assert response.status_code == status_code
    assert response.is_json
    assert response.get_json()["status"] in {"success", "error"}
    assert response.get_json()["code"] == code
    assert response.headers["Cache-Control"] == "no-store"


def _assert_private_activation_headers(response) -> None:
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Robots-Tag"] == "noindex, nofollow"


def _age_request_lock(expected_state: str) -> None:
    stale_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    with functions.get_engine().begin() as conn:
        result = conn.execute(
            functions.external_provisioning_requests_table.update()
            .where(
                functions.external_provisioning_requests_table.c.state
                == expected_state
            )
            .values(locked_at=stale_time)
        )
    assert result.rowcount == 1


def _run_concurrent_posts(
    external_api: ExternalAPIHarness,
    request_options: list[dict[str, Any]],
) -> list[Any]:
    start = Barrier(len(request_options))

    def send(options: dict[str, Any]):
        with app.app.test_client() as client:
            start.wait(timeout=10)
            return external_api.post(client=client, **options)

    with ThreadPoolExecutor(max_workers=len(request_options)) as executor:
        futures = [
            executor.submit(send, options)
            for options in request_options
        ]
        return [future.result(timeout=20) for future in futures]


def test_new_private_account_accepts_signed_multipart_request(
    external_api: ExternalAPIHarness,
) -> None:
    response = external_api.post()

    _assert_json_response(response, 201, "provisioning_completed")
    assert response.get_json()["account_state"] == "pending"
    assert response.get_json()["mail_status"] == "sent"
    assert external_api.scan_calls == [PDF_CONTENT]
    assert len(external_api.mail_calls) == 1
    assert external_api.mail_calls[0]["to_email"] == EMAIL
    assert external_api.mail_calls[0]["pdf_content"] == PDF_CONTENT
    assert "/create_user/token/" in (
        external_api.mail_calls[0]["activation_link"] or ""
    )

    with functions.get_engine().connect() as conn:
        pending_user = conn.execute(
            select(
                functions.pending_users_table.c.username,
                functions.pending_users_table.c.email,
                functions.pending_users_table.c.personnummer,
            )
        ).one()
        stored_pdf = conn.execute(
            select(
                functions.user_pdfs_table.c.content,
                functions.user_pdfs_table.c.content_sha256,
                functions.user_pdfs_table.c.categories,
                functions.user_pdfs_table.c.expires_on,
            )
        ).one()

    assert pending_user.username == NAME
    assert pending_user.email == EMAIL
    assert pending_user.personnummer == functions.hash_value(PERSONNUMMER)
    assert stored_pdf.content == PDF_CONTENT
    assert stored_pdf.content_sha256 == sha256(PDF_CONTENT).hexdigest()
    assert stored_pdf.categories == CATEGORY
    assert stored_pdf.expires_on.isoformat() == "2030-12-31"


def test_terminal_replay_returns_identical_response_without_side_effects(
    external_api: ExternalAPIHarness,
) -> None:
    idempotency_key = "same-terminal-request"

    first = external_api.post(idempotency_key=idempotency_key)
    replay = external_api.post(idempotency_key=idempotency_key)

    assert replay.status_code == first.status_code == 201
    assert replay.data == first.data
    assert len(external_api.scan_calls) == 1
    assert len(external_api.mail_calls) == 1
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.user_pdfs_table) == 1
    assert _count_rows(functions.external_provisioning_requests_table) == 1


def test_idempotency_key_rejects_a_different_fingerprint(
    external_api: ExternalAPIHarness,
) -> None:
    idempotency_key = "same-key-different-request"
    first = external_api.post(idempotency_key=idempotency_key)

    mismatch = external_api.post(
        idempotency_key=idempotency_key,
        fields={"name": "Annan Mottagare"},
    )

    assert first.status_code == 201
    _assert_json_response(mismatch, 409, "idempotency_key_reused")
    assert len(external_api.scan_calls) == 1
    assert len(external_api.mail_calls) == 1
    assert _count_rows(functions.external_provisioning_requests_table) == 1


def test_nonce_cannot_be_reused_with_a_new_idempotency_key(
    external_api: ExternalAPIHarness,
) -> None:
    nonce = "nonce-reused-1234567890"
    first = external_api.post(
        nonce=nonce,
        idempotency_key="nonce-first-request",
    )

    replay = external_api.post(
        nonce=nonce,
        idempotency_key="nonce-second-request",
    )

    assert first.status_code == 201
    _assert_json_response(replay, 409, "nonce_reused")
    assert len(external_api.scan_calls) == 1
    assert len(external_api.mail_calls) == 1
    assert _count_rows(functions.external_provisioning_requests_table) == 1


@pytest.mark.parametrize(
    ("request_options", "expected_status", "expected_code"),
    [
        (
            {"declared_pdf_sha256": sha256(b"annan-pdf").hexdigest()},
            400,
            "pdf_hash_mismatch",
        ),
        (
            {"mime_type": "text/plain"},
            415,
            "unsupported_pdf_mime",
        ),
    ],
)
def test_pdf_hash_and_mime_are_verified_before_scanning(
    external_api: ExternalAPIHarness,
    request_options: dict[str, Any],
    expected_status: int,
    expected_code: str,
) -> None:
    response = external_api.post(**request_options)

    _assert_json_response(response, expected_status, expected_code)
    assert external_api.scan_calls == []
    assert external_api.mail_calls == []
    assert _count_rows(functions.pending_users_table) == 0
    assert _count_rows(functions.user_pdfs_table) == 0


def test_retryable_mail_failure_retries_only_the_mail_step(
    external_api: ExternalAPIHarness,
) -> None:
    external_api.mail_outcomes.extend(
        [
            provisioning.email_service.EmailNotSentError(
                "SMTP avvisade utskicket."
            ),
            None,
        ]
    )
    idempotency_key = "retry-only-mail-step"

    failed = external_api.post(idempotency_key=idempotency_key)

    _assert_json_response(failed, 500, "mail_delivery_failed")
    with functions.get_engine().connect() as conn:
        failed_state = conn.execute(
            select(
                functions.external_provisioning_requests_table.c.state,
                functions.external_provisioning_requests_table.c.mail_status,
                functions.external_provisioning_requests_table.c.attempt_count,
            )
        ).one()
    assert failed_state.state == "mail_failed_retryable"
    assert failed_state.mail_status == "failed_retryable"
    assert failed_state.attempt_count == 1
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.user_pdfs_table) == 1

    retried = external_api.post(idempotency_key=idempotency_key)

    _assert_json_response(retried, 201, "provisioning_completed")
    assert retried.get_json()["mail_status"] == "sent"
    assert external_api.scan_calls == [PDF_CONTENT]
    assert len(external_api.mail_calls) == 2
    assert (
        external_api.mail_calls[0]["message_id"]
        == external_api.mail_calls[1]["message_id"]
    )
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.user_pdfs_table) == 1

    with functions.get_engine().connect() as conn:
        completed_state = conn.execute(
            select(
                functions.external_provisioning_requests_table.c.state,
                functions.external_provisioning_requests_table.c.attempt_count,
            )
        ).one()
        activation_tokens = conn.execute(
            select(
                functions.private_account_activation_tokens_table.c.superseded_at
            ).order_by(functions.private_account_activation_tokens_table.c.id)
        ).all()

    assert completed_state.state == "completed"
    assert completed_state.attempt_count == 2
    assert len(activation_tokens) == 2
    assert activation_tokens[0].superseded_at is not None
    assert activation_tokens[1].superseded_at is None
    assert (
        external_api.mail_calls[0]["activation_link"]
        != external_api.mail_calls[1]["activation_link"]
    )


def test_delivery_unknown_is_terminal_and_is_not_sent_again(
    external_api: ExternalAPIHarness,
) -> None:
    external_api.mail_outcomes.append(
        provisioning.email_service.EmailDeliveryUnknownError(
            "SMTP-svaret saknades."
        )
    )
    idempotency_key = "unknown-delivery-request"

    uncertain = external_api.post(idempotency_key=idempotency_key)
    replay = external_api.post(idempotency_key=idempotency_key)

    _assert_json_response(uncertain, 409, "delivery_unknown")
    assert replay.status_code == uncertain.status_code
    assert replay.data == uncertain.data
    assert external_api.scan_calls == [PDF_CONTENT]
    assert len(external_api.mail_calls) == 1

    with functions.get_engine().connect() as conn:
        request_state = conn.execute(
            select(
                functions.external_provisioning_requests_table.c.state,
                functions.external_provisioning_requests_table.c.mail_status,
                functions.external_provisioning_requests_table.c.attempt_count,
            )
        ).one()

    assert request_state.state == "delivery_unknown"
    assert request_state.mail_status == "delivery_unknown"
    assert request_state.attempt_count == 1


def test_active_account_ignores_a_different_incoming_email(
    external_api: ExternalAPIHarness,
) -> None:
    personnummer_hash = functions.hash_value(PERSONNUMMER)
    stored_email = functions.hash_value("befintlig@example.com")
    with functions.get_engine().begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Befintlig Användare",
                email=stored_email,
                password=functions.hash_password("hemligt-losenord"),
                personnummer=personnummer_hash,
                orgnr_normalized="",
            )
        )

    response = external_api.post(fields={"email": "ny@example.com"})

    _assert_json_response(response, 201, "provisioning_completed")
    assert response.get_json()["account_state"] == "active"
    assert response.get_json()["mail_status"] == "not_required"
    assert external_api.scan_calls == [PDF_CONTENT]
    assert external_api.mail_calls == []

    with functions.get_engine().connect() as conn:
        active_email = conn.execute(
            select(functions.users_table.c.email)
        ).scalar_one()
        pdf_owner = conn.execute(
            select(functions.user_pdfs_table.c.personnummer)
        ).scalar_one()

    assert active_email == stored_email
    assert pdf_owner == personnummer_hash
    assert _count_rows(functions.pending_users_table) == 0


def test_activation_token_is_exchanged_and_activates_account_with_safe_headers(
    external_api: ExternalAPIHarness,
) -> None:
    provisioned = external_api.post()
    assert provisioned.status_code == 201
    activation_link = external_api.mail_calls[0]["activation_link"]
    assert activation_link is not None
    activation_path = urlsplit(activation_link).path
    raw_token = activation_path.rsplit("/", 1)[1]

    exchanged = external_api.client.get(activation_path)

    assert exchanged.status_code == 303
    assert exchanged.headers["Location"].endswith("/create_user/token")
    assert raw_token not in exchanged.headers["Location"]
    _assert_private_activation_headers(exchanged)

    token_free_page = external_api.client.get("/create_user/token")
    assert token_free_page.status_code == 200
    _assert_private_activation_headers(token_free_page)
    with external_api.client.session_transaction() as session_data:
        csrf_token = session_data["csrf_token"]

    activated = external_api.client.post(
        "/create_user/token",
        data={
            "password": "nytt-sakert-losenord",
            "confirm": "nytt-sakert-losenord",
            "csrf_token": csrf_token,
        },
    )

    assert activated.status_code == 303
    assert activated.headers["Location"].endswith("/login")
    _assert_private_activation_headers(activated)
    assert _count_rows(functions.pending_users_table) == 0
    assert _count_rows(functions.users_table) == 1

    with functions.get_engine().connect() as conn:
        active_user = conn.execute(
            select(
                functions.users_table.c.email,
                functions.users_table.c.password,
            )
        ).one()
        used_at = conn.execute(
            select(
                functions.private_account_activation_tokens_table.c.used_at
            )
        ).scalar_one()

    assert active_user.email == EMAIL
    assert functions.verify_password(
        active_user.password,
        "nytt-sakert-losenord",
    )
    assert used_at is not None

    used_link = external_api.client.get(activation_path)
    assert used_link.status_code == 404
    _assert_private_activation_headers(used_link)


def test_only_one_external_route_is_registered_and_errors_are_json(
    external_api: ExternalAPIHarness,
    monkeypatch,
) -> None:
    external_rules = [
        rule
        for rule in app.app.url_map.iter_rules()
        if rule.rule.startswith("/api/external/")
    ]
    assert len(external_rules) == 1
    assert external_rules[0].rule == ROUTE
    assert external_rules[0].methods - {"OPTIONS"} == {"POST"}

    not_found = external_api.client.get("/api/external/okand-rutt")
    method_not_allowed = external_api.client.get(ROUTE)
    options_not_allowed = external_api.client.options(ROUTE)

    _assert_json_response(not_found, 404, "external_route_not_found")
    _assert_json_response(method_not_allowed, 405, "method_not_allowed")
    _assert_json_response(
        options_not_allowed,
        405,
        "method_not_allowed",
    )

    monkeypatch.setenv("EXTERNAL_PROVISIONING_MAX_PDF_BYTES", "16")
    too_large = external_api.post()

    _assert_json_response(too_large, 413, "pdf_too_large")
    assert external_api.scan_calls == []
    assert external_api.mail_calls == []

    monkeypatch.setitem(app.app.config, "MAX_CONTENT_LENGTH", 16)
    globally_too_large = external_api.post()

    _assert_json_response(globally_too_large, 413, "pdf_too_large")


def test_active_account_with_matching_email_receives_document_email(
    external_api: ExternalAPIHarness,
) -> None:
    personnummer_hash = functions.hash_value(PERSONNUMMER)
    with functions.get_engine().begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Aktiv Användare",
                email=EMAIL,
                password=functions.hash_password("befintligt-losenord"),
                personnummer=personnummer_hash,
                orgnr_normalized="",
            )
        )

    response = external_api.post()

    _assert_json_response(response, 201, "provisioning_completed")
    assert response.get_json()["account_state"] == "active"
    assert response.get_json()["mail_status"] == "sent"
    assert external_api.scan_calls == [PDF_CONTENT]
    assert len(external_api.mail_calls) == 1
    assert external_api.mail_calls[0]["to_email"] == EMAIL
    assert external_api.mail_calls[0]["activation_link"] is None
    assert _count_rows(functions.pending_users_table) == 0
    assert _count_rows(functions.user_pdfs_table) == 1


def test_pending_account_is_updated_instead_of_duplicated(
    external_api: ExternalAPIHarness,
) -> None:
    personnummer_hash = functions.hash_value(PERSONNUMMER)
    with functions.get_engine().begin() as conn:
        conn.execute(
            functions.pending_users_table.insert().values(
                username="Gammalt Namn",
                email="gammal@example.com",
                personnummer=personnummer_hash,
                orgnr_normalized="",
            )
        )

    response = external_api.post()

    _assert_json_response(response, 201, "provisioning_completed")
    assert response.get_json()["account_state"] == "pending"
    assert _count_rows(functions.pending_users_table) == 1
    with functions.get_engine().connect() as conn:
        pending_user = conn.execute(
            select(
                functions.pending_users_table.c.username,
                functions.pending_users_table.c.email,
                functions.pending_users_table.c.personnummer,
            )
        ).one()

    assert pending_user.username == NAME
    assert pending_user.email == EMAIL
    assert pending_user.personnummer == personnummer_hash
    assert len(external_api.mail_calls) == 1
    assert external_api.mail_calls[0]["activation_link"] is not None


@pytest.mark.parametrize("storage_format", ["normalized", "legacy_hash"])
def test_email_conflict_detects_normalized_and_legacy_storage(
    external_api: ExternalAPIHarness,
    storage_format: str,
) -> None:
    stored_email = (
        EMAIL
        if storage_format == "normalized"
        else functions.hash_value(EMAIL)
    )
    with functions.get_engine().begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Annan Användare",
                email=stored_email,
                password=functions.hash_password("befintligt-losenord"),
                personnummer=functions.hash_value("9102021234"),
                orgnr_normalized="",
            )
        )

    response = external_api.post()

    _assert_json_response(response, 409, "email_conflict")
    assert external_api.scan_calls == [PDF_CONTENT]
    assert external_api.mail_calls == []
    assert _count_rows(functions.pending_users_table) == 0
    assert _count_rows(functions.user_pdfs_table) == 0


@pytest.mark.parametrize(
    "account_kind",
    ["company_account", "supervisor", "company_connected_private"],
)
def test_unsupported_account_types_are_rejected(
    external_api: ExternalAPIHarness,
    account_kind: str,
) -> None:
    with functions.get_engine().begin() as conn:
        if account_kind == "company_account":
            conn.execute(
                functions.company_users_table.insert().values(
                    role="foretagskonto",
                    name="Företagskonto",
                    email=EMAIL,
                )
            )
        elif account_kind == "supervisor":
            conn.execute(
                functions.supervisors_table.insert().values(
                    name="Handledare",
                    email=EMAIL,
                    password=functions.hash_password("befintligt-losenord"),
                )
            )
        else:
            conn.execute(
                functions.users_table.insert().values(
                    username="Företagskopplad Privatperson",
                    email=EMAIL,
                    password=functions.hash_password(
                        "befintligt-losenord"
                    ),
                    personnummer=functions.hash_value(PERSONNUMMER),
                    orgnr_normalized="5569668337",
                )
            )

    response = external_api.post()

    _assert_json_response(response, 409, "account_type_not_allowed")
    assert external_api.scan_calls == [PDF_CONTENT]
    assert external_api.mail_calls == []
    assert _count_rows(functions.pending_users_table) == 0
    assert _count_rows(functions.user_pdfs_table) == 0


@pytest.mark.parametrize(
    ("auth_failure", "expected_code"),
    [
        ("invalid_signature", "invalid_signature"),
        ("old_timestamp", "timestamp_outside_window"),
        ("unknown_key", "unknown_key_id"),
    ],
)
def test_hmac_authentication_failures_are_rejected_before_claiming_request(
    external_api: ExternalAPIHarness,
    auth_failure: str,
    expected_code: str,
) -> None:
    request_options: dict[str, Any] = {}
    if auth_failure == "invalid_signature":
        request_options["signature_override"] = "0" * 64
    elif auth_failure == "old_timestamp":
        request_options["timestamp"] = str(int(time()) - 600)
    else:
        request_options["key_id"] = "unknown-partner"

    response = external_api.post(**request_options)

    _assert_json_response(response, 401, expected_code)
    assert external_api.scan_calls == []
    assert external_api.mail_calls == []
    assert _count_rows(functions.external_provisioning_nonces_table) == 0
    assert _count_rows(functions.external_provisioning_requests_table) == 0


def test_replay_windows_cannot_be_weakened_by_environment(
    external_api: ExternalAPIHarness,
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "EXTERNAL_PROVISIONING_TIMESTAMP_WINDOW_SECONDS",
        "86400",
    )
    stale = external_api.post(timestamp=str(int(time()) - 600))

    _assert_json_response(
        stale,
        401,
        "timestamp_outside_window",
    )

    monkeypatch.setenv("EXTERNAL_PROVISIONING_NONCE_TTL_HOURS", "1")
    accepted = external_api.post()

    assert accepted.status_code == 201
    with functions.get_engine().connect() as conn:
        nonce_row = conn.execute(
            select(
                functions.external_provisioning_nonces_table.c.created_at,
                functions.external_provisioning_nonces_table.c.expires_at,
            )
        ).one()
    created_at = nonce_row.created_at
    expires_at = nonce_row.expires_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    assert timedelta(hours=23, minutes=59) <= (
        expires_at - created_at
    ) <= timedelta(hours=24, minutes=1)


def test_same_pdf_with_new_idempotency_key_is_a_document_conflict(
    external_api: ExternalAPIHarness,
) -> None:
    first = external_api.post(idempotency_key="first-document-request")
    duplicate = external_api.post(
        idempotency_key="second-document-request"
    )

    assert first.status_code == 201
    _assert_json_response(duplicate, 409, "document_already_exists")
    assert external_api.scan_calls == [PDF_CONTENT, PDF_CONTENT]
    assert len(external_api.mail_calls) == 1
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.user_pdfs_table) == 1
    assert _count_rows(functions.private_account_activation_tokens_table) == 1
    assert _count_rows(functions.external_provisioning_requests_table) == 2


@pytest.mark.parametrize(
    "token_state",
    ["expired", "used", "revoked", "superseded"],
)
def test_invalid_activation_token_states_are_rejected(
    external_api: ExternalAPIHarness,
    token_state: str,
) -> None:
    provisioned = external_api.post()
    assert provisioned.status_code == 201
    activation_link = external_api.mail_calls[0]["activation_link"]
    assert activation_link is not None
    activation_path = urlsplit(activation_link).path
    raw_token = activation_path.rsplit("/", 1)[1]
    now = datetime.now(timezone.utc)
    values = (
        {"expires_at": now - timedelta(seconds=1)}
        if token_state == "expired"
        else {f"{token_state}_at": now}
    )
    with functions.get_engine().begin() as conn:
        conn.execute(
            functions.private_account_activation_tokens_table.update().values(
                **values
            )
        )

    assert not provisioning.get_activation_token_status(token=raw_token).valid
    rejected = external_api.client.get(activation_path)

    assert rejected.status_code == 404
    _assert_private_activation_headers(rejected)
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.users_table) == 0


def test_scanner_timeout_is_retryable_and_does_not_store_business_data(
    external_api: ExternalAPIHarness,
) -> None:
    external_api.scan_outcomes.append(
        provisioning.PDFScannerTimeoutError("Skanningen tog för lång tid.")
    )

    response = external_api.post()

    _assert_json_response(response, 500, "pdf_scanner_timeout")
    assert external_api.scan_calls == [PDF_CONTENT]
    assert external_api.mail_calls == []
    assert _count_rows(functions.pending_users_table) == 0
    assert _count_rows(functions.user_pdfs_table) == 0
    with functions.get_engine().connect() as conn:
        request_state = conn.execute(
            select(
                functions.external_provisioning_requests_table.c.state,
                functions.external_provisioning_requests_table.c.locked_at,
                functions.external_provisioning_requests_table.c.attempt_count,
            )
        ).one()

    assert request_state.state == "processing"
    assert request_state.locked_at is None
    assert request_state.attempt_count == 1


@pytest.mark.parametrize(
    ("additional_fields", "expected_code"),
    [
        ([("name", "Dubblettnamn")], "duplicate_field"),
        ([("ovantat_falt", "värde")], "unknown_field"),
    ],
)
def test_duplicate_and_unknown_multipart_fields_are_rejected(
    external_api: ExternalAPIHarness,
    additional_fields: list[tuple[str, Any]],
    expected_code: str,
) -> None:
    response = external_api.post(
        additional_form_fields=additional_fields
    )

    _assert_json_response(response, 400, expected_code)
    assert external_api.scan_calls == []
    assert external_api.mail_calls == []
    assert _count_rows(functions.external_provisioning_nonces_table) == 0
    assert _count_rows(functions.external_provisioning_requests_table) == 0


def test_key_rotation_accepts_both_configured_key_ids(
    external_api: ExternalAPIHarness,
    monkeypatch,
) -> None:
    rotated_key_id = "rotated-partner"
    rotated_secret = "rotated-external-secret-that-is-also-at-least-32-bytes"
    monkeypatch.setenv(
        "EXTERNAL_PROVISIONING_HMAC_KEYS",
        (
            f'{{"{KEY_ID}":"{HMAC_SECRET}",'
            f'"{rotated_key_id}":"{rotated_secret}"}}'
        ),
    )

    original_key = external_api.post(idempotency_key="original-key-request")
    rotated_key = external_api.post(
        idempotency_key="rotated-key-request",
        key_id=rotated_key_id,
        hmac_secret=rotated_secret,
        fields={
            "personal_identity_number": "9102021234",
            "email": "bo@example.com",
            "name": "Bo Berg",
        },
    )

    assert original_key.status_code == 201
    assert rotated_key.status_code == 201
    assert len(external_api.scan_calls) == 2
    assert len(external_api.mail_calls) == 2
    assert {
        call["to_email"] for call in external_api.mail_calls
    } == {EMAIL, "bo@example.com"}
    assert _count_rows(functions.external_provisioning_requests_table) == 2


def test_production_startup_rejects_disabled_email(monkeypatch) -> None:
    monkeypatch.setenv("EXTERNAL_PRIVATE_PROVISIONING_ENABLED", "true")
    monkeypatch.setenv(
        "EXTERNAL_PROVISIONING_HMAC_KEYS",
        f'{{"{KEY_ID}":"{HMAC_SECRET}"}}',
    )
    monkeypatch.setenv("EXTERNAL_PROVISIONING_MAX_PDF_BYTES", "1048576")
    monkeypatch.setenv("EXTERNAL_PROVISIONING_MIN_SECRET_LENGTH", "32")
    monkeypatch.setenv("BASE_URL", "https://intyg.example")
    monkeypatch.setenv("DEV_MODE", "false")
    monkeypatch.setenv("DISABLE_EMAILS", "true")

    with pytest.raises(RuntimeError, match="DISABLE_EMAILS=true"):
        provisioning.validate_startup_configuration()


def test_production_startup_requires_secure_session_cookie(
    monkeypatch,
) -> None:
    monkeypatch.setenv("EXTERNAL_PRIVATE_PROVISIONING_ENABLED", "true")
    monkeypatch.setenv(
        "EXTERNAL_PROVISIONING_HMAC_KEYS",
        f'{{"{KEY_ID}":"{HMAC_SECRET}"}}',
    )
    monkeypatch.setenv("BASE_URL", "https://intyg.example")
    monkeypatch.setenv("DEV_MODE", "false")
    monkeypatch.setenv("DISABLE_EMAILS", "false")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")

    with pytest.raises(RuntimeError, match="SESSION_COOKIE_SECURE=true"):
        provisioning.validate_startup_configuration()


def test_legacy_private_activation_and_confirmation_page_still_work(
    external_api: ExternalAPIHarness,
) -> None:
    legacy_personnummer = "9203031234"
    personnummer_hash = functions.hash_value(legacy_personnummer)
    with functions.get_engine().begin() as conn:
        conn.execute(
            functions.pending_users_table.insert().values(
                username="Legacy Användare",
                email=functions.hash_value("legacy@example.com"),
                personnummer=personnummer_hash,
                orgnr_normalized="",
            )
        )

    activation_page = external_api.client.get(
        f"/create_user/{personnummer_hash}"
    )
    activated = external_api.client.post(
        f"/create_user/{personnummer_hash}",
        data={
            "password": "legacy-losenord",
            "confirm": "legacy-losenord",
        },
    )
    confirmation_page = external_api.client.get(
        "/ansok/standardkonto/klart"
    )

    assert activation_page.status_code == 200
    assert "Skapa konto" in activation_page.get_data(as_text=True)
    assert activated.status_code == 302
    assert activated.headers["Location"].endswith("/login")
    assert confirmation_page.status_code == 200
    assert "Kontrollera din e-post" in confirmation_page.get_data(
        as_text=True
    )
    assert _count_rows(functions.pending_users_table) == 0
    assert _count_rows(functions.users_table) == 1


def test_stale_processing_request_is_taken_over_without_duplicate_data(
    external_api: ExternalAPIHarness,
) -> None:
    idempotency_key = "stale-processing-takeover"
    external_api.scan_outcomes.append(
        SimulatedWorkerCrash("worker stopped during scanning")
    )

    with pytest.raises(SimulatedWorkerCrash):
        external_api.post(idempotency_key=idempotency_key)

    _age_request_lock("processing")
    recovered = external_api.post(idempotency_key=idempotency_key)

    _assert_json_response(recovered, 201, "provisioning_completed")
    assert external_api.scan_calls == [PDF_CONTENT, PDF_CONTENT]
    assert len(external_api.mail_calls) == 1
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.user_pdfs_table) == 1
    assert _count_rows(functions.external_provisioning_requests_table) == 1
    with functions.get_engine().connect() as conn:
        request_state = conn.execute(
            select(
                functions.external_provisioning_requests_table.c.state,
                functions.external_provisioning_requests_table.c.attempt_count,
            )
        ).one()

    assert request_state.state == "completed"
    assert request_state.attempt_count == 2


def test_stale_mail_sending_becomes_delivery_unknown_without_resend(
    external_api: ExternalAPIHarness,
) -> None:
    idempotency_key = "stale-mail-sending"
    external_api.mail_outcomes.append(
        SimulatedWorkerCrash("worker stopped after SMTP started")
    )

    with pytest.raises(SimulatedWorkerCrash):
        external_api.post(idempotency_key=idempotency_key)

    _age_request_lock("mail_sending")
    recovered = external_api.post(idempotency_key=idempotency_key)

    _assert_json_response(recovered, 409, "delivery_unknown")
    assert external_api.scan_calls == [PDF_CONTENT]
    assert len(external_api.mail_calls) == 1
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.user_pdfs_table) == 1
    with functions.get_engine().connect() as conn:
        request_state = conn.execute(
            select(
                functions.external_provisioning_requests_table.c.state,
                functions.external_provisioning_requests_table.c.mail_status,
                functions.external_provisioning_requests_table.c.attempt_count,
            )
        ).one()

    assert request_state.state == "delivery_unknown"
    assert request_state.mail_status == "delivery_unknown"
    assert request_state.attempt_count == 1


def test_crash_after_storage_commit_recovers_with_mail_only(
    external_api: ExternalAPIHarness,
    monkeypatch,
) -> None:
    original_send_mail = provisioning._send_mail
    should_crash = True

    def crash_once_before_mail(context, activation_url_builder):
        nonlocal should_crash
        if should_crash:
            should_crash = False
            raise SimulatedWorkerCrash(
                "worker stopped after the storage commit"
            )
        return original_send_mail(context, activation_url_builder)

    monkeypatch.setattr(provisioning, "_send_mail", crash_once_before_mail)
    idempotency_key = "storage-committed-before-mail"

    with pytest.raises(SimulatedWorkerCrash):
        external_api.post(idempotency_key=idempotency_key)

    assert external_api.scan_calls == [PDF_CONTENT]
    assert external_api.mail_calls == []
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.user_pdfs_table) == 1
    _age_request_lock("stored_mail_pending")

    recovered = external_api.post(idempotency_key=idempotency_key)

    _assert_json_response(recovered, 201, "provisioning_completed")
    assert external_api.scan_calls == [PDF_CONTENT]
    assert len(external_api.mail_calls) == 1
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.user_pdfs_table) == 1
    assert _count_rows(functions.private_account_activation_tokens_table) == 2
    with functions.get_engine().connect() as conn:
        request_state = conn.execute(
            select(
                functions.external_provisioning_requests_table.c.state,
                functions.external_provisioning_requests_table.c.attempt_count,
            )
        ).one()

    assert request_state.state == "completed"
    assert request_state.attempt_count == 2


def test_concurrent_same_idempotency_has_one_set_of_side_effects(
    external_api: ExternalAPIHarness,
    monkeypatch,
) -> None:
    original_register_nonce = provisioning._register_nonce
    both_nonces_registered = Barrier(2)

    def register_then_wait(command) -> None:
        original_register_nonce(command)
        both_nonces_registered.wait(timeout=10)

    monkeypatch.setattr(
        provisioning,
        "_register_nonce",
        register_then_wait,
    )
    responses = _run_concurrent_posts(
        external_api,
        [
            {
                "idempotency_key": "concurrent-same-idempotency",
                "nonce": "concurrent-idem-nonce-0001",
            },
            {
                "idempotency_key": "concurrent-same-idempotency",
                "nonce": "concurrent-idem-nonce-0002",
            },
        ],
    )

    statuses = [response.status_code for response in responses]
    assert statuses.count(201) >= 1
    assert set(statuses) <= {201, 425}
    for response in responses:
        if response.status_code == 425:
            assert response.get_json()["code"] == "request_in_progress"
    if statuses == [201, 201]:
        assert responses[0].data == responses[1].data
    assert len(external_api.mail_calls) == 1
    assert _count_rows(functions.external_provisioning_requests_table) == 1
    assert _count_rows(functions.external_provisioning_nonces_table) == 2
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.user_pdfs_table) == 1


def test_concurrent_same_nonce_allows_exactly_one_request(
    external_api: ExternalAPIHarness,
    monkeypatch,
) -> None:
    original_register_nonce = provisioning._register_nonce
    both_requests_ready = Barrier(2)

    def wait_then_register(command) -> None:
        both_requests_ready.wait(timeout=10)
        original_register_nonce(command)

    monkeypatch.setattr(
        provisioning,
        "_register_nonce",
        wait_then_register,
    )
    shared_nonce = "concurrent-shared-nonce-0001"
    responses = _run_concurrent_posts(
        external_api,
        [
            {
                "idempotency_key": "concurrent-nonce-request-1",
                "nonce": shared_nonce,
            },
            {
                "idempotency_key": "concurrent-nonce-request-2",
                "nonce": shared_nonce,
            },
        ],
    )

    outcomes = {
        (response.status_code, response.get_json()["code"])
        for response in responses
    }
    assert outcomes == {
        (201, "provisioning_completed"),
        (409, "nonce_reused"),
    }
    assert len(external_api.mail_calls) == 1
    assert _count_rows(functions.external_provisioning_nonces_table) == 1
    assert _count_rows(functions.external_provisioning_requests_table) == 1
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.user_pdfs_table) == 1


def test_concurrent_same_pdf_with_different_idempotency_is_constrained(
    external_api: ExternalAPIHarness,
    monkeypatch,
) -> None:
    original_store = provisioning._store_initial_provisioning
    both_requests_scanned = Barrier(2)
    sqlite_storage_lock = Lock()

    def synchronized_store(command, claim, content):
        both_requests_scanned.wait(timeout=10)
        with sqlite_storage_lock:
            return original_store(command, claim, content)

    monkeypatch.setattr(
        provisioning,
        "_store_initial_provisioning",
        synchronized_store,
    )
    responses = _run_concurrent_posts(
        external_api,
        [
            {
                "idempotency_key": "concurrent-document-request-1",
                "nonce": "concurrent-document-nonce-0001",
            },
            {
                "idempotency_key": "concurrent-document-request-2",
                "nonce": "concurrent-document-nonce-0002",
            },
        ],
    )

    outcomes = {
        (response.status_code, response.get_json()["code"])
        for response in responses
    }
    assert outcomes == {
        (201, "provisioning_completed"),
        (409, "document_already_exists"),
    }
    assert external_api.scan_calls == [PDF_CONTENT, PDF_CONTENT]
    assert len(external_api.mail_calls) == 1
    assert _count_rows(functions.external_provisioning_requests_table) == 2
    assert _count_rows(functions.external_provisioning_nonces_table) == 2
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.user_pdfs_table) == 1


def test_direct_token_post_validation_error_can_recover_token_free(
    external_api: ExternalAPIHarness,
) -> None:
    provisioned = external_api.post()
    assert provisioned.status_code == 201
    activation_link = external_api.mail_calls[0]["activation_link"]
    assert activation_link is not None
    activation_path = urlsplit(activation_link).path

    invalid = external_api.client.post(
        activation_path,
        data={
            "password": "for-kort",
            "confirm": "matchar-inte",
        },
    )

    assert invalid.status_code == 400
    assert "Lösenorden måste matcha." in invalid.get_data(as_text=True)
    _assert_private_activation_headers(invalid)
    assert _count_rows(functions.pending_users_table) == 1
    assert _count_rows(functions.users_table) == 0

    token_free_page = external_api.client.get("/create_user/token")
    assert token_free_page.status_code == 200
    _assert_private_activation_headers(token_free_page)
    with external_api.client.session_transaction() as session_data:
        csrf_token = session_data["csrf_token"]

    corrected = external_api.client.post(
        "/create_user/token",
        data={
            "password": "korrigerat-losenord",
            "confirm": "korrigerat-losenord",
            "csrf_token": csrf_token,
        },
    )

    assert corrected.status_code == 303
    assert corrected.headers["Location"].endswith("/login")
    _assert_private_activation_headers(corrected)
    assert _count_rows(functions.pending_users_table) == 0
    assert _count_rows(functions.users_table) == 1


def test_concurrent_activation_claims_token_exactly_once(
    external_api: ExternalAPIHarness,
) -> None:
    provisioned = external_api.post()
    assert provisioned.status_code == 201
    activation_link = external_api.mail_calls[0]["activation_link"]
    assert activation_link is not None
    raw_token = urlsplit(activation_link).path.rsplit("/", 1)[1]
    ready = Barrier(2)

    def activate(password: str) -> bool:
        ready.wait(timeout=10)
        return provisioning.activate_private_account(
            password,
            token=raw_token,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                activate,
                ("samtidigt-losenord-1", "samtidigt-losenord-2"),
            )
        )

    assert sorted(results) == [False, True]
    assert _count_rows(functions.pending_users_table) == 0
    assert _count_rows(functions.users_table) == 1
    assert not provisioning.get_activation_token_status(
        token=raw_token
    ).valid


# Copyright (c) Liam Suorsa and Mika Suorsa
