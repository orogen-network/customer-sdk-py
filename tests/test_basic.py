"""Basic tests for orogen_sdk SDK."""

from __future__ import annotations

import json

import respx
from httpx import Response
from mining_types.crypto import generate_keypair, sign_ed25519

from orogen_sdk import (
    OrogenClient,
    VerificationResult,
    generate_nonce,
    verify_receipt,
)
from orogen_sdk.client import canonical_request_hash
from orogen_sdk.nonce import current_timestamp_ms
from orogen_sdk.types import KvMetadata, Receipt


def test_generate_nonce_is_unique() -> None:
    a = generate_nonce()
    b = generate_nonce()
    assert a != b
    assert a.startswith("0x")
    assert len(a) == 66  # 0x + 64 hex chars = 32 bytes


def test_canonical_request_hash_stable() -> None:
    msgs1 = [{"role": "user", "content": "hi"}]
    msgs2 = [{"content": "hi", "role": "user"}]  # different key order
    assert canonical_request_hash(msgs1) == canonical_request_hash(msgs2)


def _unsigned_receipt(nonce: str = "0x" + "ab" * 32) -> Receipt:
    return Receipt(
        version=1,
        job_id="0x" + "01" * 32,
        operator_id="5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV",
        model_id="0x" + "02" * 32,
        model_weight_hash="0x" + "03" * 32,
        customer_nonce=nonce,
        request_hash="0x" + "04" * 32,
        response_hash="0x" + "05" * 32,
        log_probs_sample="AAA=",
        kv_metadata=KvMetadata(),
        kernel_pack_hash="0x" + "06" * 32,
        gpu_model="H100-SXM-80GB",
        driver_version="550.54",
        cuda_version="12.4",
        attestation_report_hash="0x" + "07" * 32,
        timestamp_ms=current_timestamp_ms(),
        gateway_id="5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV",
        operator_signature="",
    )


def _signed_receipt(priv_hex: str, nonce: str = "0x" + "ab" * 32) -> Receipt:
    r = _unsigned_receipt(nonce=nonce)
    sig_hex = sign_ed25519(priv_hex, r.signing_payload())
    return r.model_copy(update={"operator_signature": sig_hex})


def test_verify_receipt_happy_path_with_pubkey() -> None:
    """M-W-05: overall=True only when a real ed25519 verification passes."""
    priv_hex, pub_hex = generate_keypair()
    nonce = generate_nonce()
    receipt = _signed_receipt(priv_hex, nonce=nonce)
    result = verify_receipt(receipt, operator_pubkey_hex=pub_hex, expected_nonce=nonce)
    assert isinstance(result, VerificationResult)
    assert result.signature_well_formed is True
    assert result.signature_verified is True
    assert result.overall is True


def test_verify_receipt_overall_false_without_pubkey() -> None:
    """M-W-05: without operator_pubkey_hex, overall MUST be False.

    The previous behaviour was that a 64-char string passed `signature_valid`
    and `overall` was True — now `signature_verified` is False, so `overall`
    is False even on a "happy" length check.
    """
    priv_hex, _ = generate_keypair()
    receipt = _signed_receipt(priv_hex)
    result = verify_receipt(receipt)
    assert result.signature_well_formed is True
    assert result.signature_verified is False
    assert result.overall is False


def test_verify_receipt_overall_false_with_wrong_pubkey() -> None:
    """A receipt signed by op-A but verified against op-B's pubkey MUST fail."""
    priv_a, _ = generate_keypair()
    _, pub_b = generate_keypair()
    receipt = _signed_receipt(priv_a)
    result = verify_receipt(receipt, operator_pubkey_hex=pub_b)
    assert result.signature_well_formed is True
    assert result.signature_verified is False
    assert result.overall is False


def test_verify_receipt_stale_attestation() -> None:
    priv_hex, pub_hex = generate_keypair()
    receipt = _signed_receipt(priv_hex)
    # Time the receipt 8 days in the past — default window is 7d.
    # Re-sign over the stale payload.
    stale = receipt.model_copy(update={"timestamp_ms": current_timestamp_ms() - (8 * 24 * 60 * 60 * 1000)})
    re_sig = sign_ed25519(priv_hex, stale.signing_payload())
    stale = stale.model_copy(update={"operator_signature": re_sig})
    result = verify_receipt(stale, operator_pubkey_hex=pub_hex)
    assert result.signature_verified is True
    assert result.attestation_fresh is False
    assert result.overall is False


def test_verify_receipt_unknown_model() -> None:
    priv_hex, pub_hex = generate_keypair()
    receipt = _signed_receipt(priv_hex)
    result = verify_receipt(
        receipt, operator_pubkey_hex=pub_hex, known_models={"0x" + "ff" * 32}
    )
    assert result.model_in_registry is False
    assert result.overall is False


def test_verify_receipt_bad_signature_shape() -> None:
    receipt = _unsigned_receipt()
    receipt.operator_signature = "short"
    result = verify_receipt(receipt)
    assert result.signature_well_formed is False
    assert result.signature_verified is False
    assert result.overall is False


def test_verify_receipt_forged_64char_signature_no_pubkey() -> None:
    """The audit's primary M-W-05 footgun: a 64-char garbage string used to
    pass `signature_valid` and flip `overall` to True. Now `signature_verified`
    is False and `overall` is False even without a pubkey supplied."""
    receipt = _unsigned_receipt()
    receipt.operator_signature = "f" * 128  # well-formed hex shape, but garbage
    result = verify_receipt(receipt)
    assert result.signature_well_formed is True
    assert result.signature_verified is False
    assert result.overall is False


@respx.mock
def test_fetch_nonce_via_gateway() -> None:
    fake_nonce = "0x" + "11" * 32
    respx.post("https://test/v1/nonces").mock(return_value=Response(200, json={"nonce": fake_nonce}))
    with OrogenClient(api_key="test", base_url="https://test/v1") as client:
        n = client.fetch_nonce()
    assert n == fake_nonce


@respx.mock
def test_default_gateway_issued_mode_pre_fetches_nonce() -> None:
    fake_nonce = "0x" + "22" * 32
    fake_response = {
        "id": "cmpl-2",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "x",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
    respx.post("https://test/v1/nonces").mock(return_value=Response(200, json={"nonce": fake_nonce}))
    respx.post("https://test/v1/chat/completions").mock(return_value=Response(200, json=fake_response))
    with OrogenClient(api_key="test", base_url="https://test/v1") as client:
        response = client.chat.completions.create(model="x", messages=[{"role": "user", "content": "hi"}])
    assert response.choices[0]["message"]["content"] == "hi"


@respx.mock
def test_client_routes_request_no_useful_nonce_alias_on_wire() -> None:
    """M-W-06: the SDK sends `customer_nonce` only — the `useful_nonce` alias
    is no longer included in the wire body."""
    priv_hex, _ = generate_keypair()
    nonce = generate_nonce()
    receipt = _signed_receipt(priv_hex, nonce=nonce)

    captured: dict[str, object] = {}

    def _capture(request):  # type: ignore[no-untyped-def]
        captured["body"] = request.content
        return Response(
            200,
            json={
                "id": "cmpl-1",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "llama-3.1-70b-instruct",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
                "useful_receipt": receipt.model_dump(mode="json"),
            },
        )

    respx.post("https://test/v1/chat/completions").mock(side_effect=_capture)

    with OrogenClient(api_key="test", base_url="https://test/v1") as client:
        response = client.chat.completions.create(
            model="llama-3.1-70b-instruct",
            messages=[{"role": "user", "content": "hi"}],
            useful_nonce=nonce,
        )
    assert response.choices[0]["message"]["content"] == "hi"
    body = json.loads(captured["body"])
    assert body.get("customer_nonce") == nonce
    assert "useful_nonce" not in body  # M-W-06 — alias is gone


@respx.mock
def test_client_verify_receipt_requires_pubkey_for_overall_true() -> None:
    priv_hex, pub_hex = generate_keypair()
    nonce = generate_nonce()
    receipt = _signed_receipt(priv_hex, nonce=nonce)
    response_json = {
        "id": "cmpl-verify",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "x",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
        "useful_receipt": receipt.model_dump(mode="json"),
    }
    respx.post("https://test/v1/chat/completions").mock(
        side_effect=[
            Response(200, json=response_json),
            Response(200, json=response_json),
        ]
    )
    with OrogenClient(api_key="test", base_url="https://test/v1") as client:
        without_key = client.chat.completions.create(
            model="x",
            messages=[{"role": "user", "content": "hi"}],
            useful_nonce=nonce,
            useful_verify_receipt=True,
        )
    assert without_key.useful_verification is not None
    assert without_key.useful_verification.signature_verified is False
    assert without_key.useful_verification.overall is False

    with OrogenClient(api_key="test", base_url="https://test/v1") as client:
        with_key = client.chat.completions.create(
            model="x",
            messages=[{"role": "user", "content": "hi"}],
            useful_nonce=nonce,
            useful_verify_receipt=True,
            useful_operator_pubkey_hex=pub_hex,
        )
    assert with_key.useful_verification is not None
    assert with_key.useful_verification.overall is True
