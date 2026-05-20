"""Client-side receipt verification (RFC-0001).

Customer can opt in to receipt verification per-request via
`useful_verify_receipt=True`. This is best-effort client-side validation;
authoritative verification happens on-chain by validators (RFC-0006 sampling).

Security audit M-W-05 / M-W-08
------------------------------
The previous `verify_receipt` declared `signature_valid = True` whenever the
signature string was ≥64 chars — i.e. a length check that any 64-char string
would pass. That was a usability foot-gun: customers thought they had
cryptographically validated provenance when they had not.

`verify_receipt` now takes an explicit `operator_pubkey_hex` argument. If it
is omitted, `signature_well_formed` is reported (shape check) but
`signature_verified` is False — and `overall` is therefore False. If it is
supplied, the receipt's canonical `signing_payload()` bytes are fed through
`mining_types.crypto.verify_ed25519` against `receipt.operator_signature`.

`tier_matches` was removed entirely — it was always True, with the comment
"defer to gateway". Tier validation lives in the linked attestation report
(RFC-0002) and is performed there, not here.
"""

from __future__ import annotations

import base64

from mining_types.crypto import verify_ed25519

from orogen_sdk.nonce import current_timestamp_ms
from orogen_sdk.types import Receipt, VerificationResult


def _signature_well_formed(sig: str | None) -> bool:
    """Cheap shape check: hex 128 chars (= 64 bytes) OR ≥64 chars of base64.

    The on-chain canonical form is hex; we accept both shapes because some
    gateway implementations historically emitted base64.
    """
    if not isinstance(sig, str) or len(sig) < 64:
        return False
    # Hex sigs are exactly 128 characters.
    if len(sig) == 128:
        try:
            bytes.fromhex(sig)
            return True
        except ValueError:
            return False
    # Otherwise treat as base64-ish — must decode and be 64 bytes.
    try:
        b = base64.b64decode(sig, validate=True)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return False
    return len(b) == 64


def verify_receipt(
    receipt: Receipt,
    *,
    operator_pubkey_hex: str | None = None,
    expected_nonce: str | None = None,
    known_models: set[str] | None = None,
    now_ms: int | None = None,
    attestation_validity_window_ms: int = 7 * 24 * 60 * 60 * 1000,
) -> VerificationResult:
    """Verify a receipt against caller-known expectations.

    Args:
        receipt: the parsed receipt to check.
        operator_pubkey_hex: ed25519 public key of the operator that issued
            the receipt, hex-encoded (64 chars). Required for
            `signature_verified` / `overall` to be True. Without it, only a
            shape check is performed and `overall` is False (security audit
            M-W-05 — verify_receipt no longer reports `overall = True`
            without a real cryptographic check).
        expected_nonce: if provided, must equal `receipt.customer_nonce`.
        known_models: if provided, `receipt.model_id` must be a member.
        now_ms: override for current time (testing only).
        attestation_validity_window_ms: max age of the receipt before it is
            considered stale.

    Returns:
        VerificationResult with per-check booleans + overall. `overall` is
        True only when every gated check passes AND `signature_verified is
        True` — never on the shape check alone.
    """

    sig_well_formed = _signature_well_formed(receipt.operator_signature)

    signature_verified = False
    if sig_well_formed and operator_pubkey_hex is not None:
        # Real ed25519 verification against the canonical signing payload.
        # `verify_ed25519` is fail-closed: any malformed input returns False
        # rather than raising.
        sig_hex = receipt.operator_signature
        if len(sig_hex) != 128:
            # Convert base64 → hex so verify_ed25519 sees the canonical form.
            try:
                sig_hex = base64.b64decode(sig_hex, validate=True).hex()
            except Exception:
                sig_hex = ""
        signature_verified = verify_ed25519(
            operator_pubkey_hex, receipt.signing_payload(), sig_hex,
        )

    if now_ms is None:
        now_ms = current_timestamp_ms()
    attestation_fresh = (now_ms - receipt.timestamp_ms) < attestation_validity_window_ms

    nonce_unique = expected_nonce is None or receipt.customer_nonce == expected_nonce

    model_in_registry = known_models is None or receipt.model_id in known_models

    # `overall` REQUIRES `signature_verified is True`; the previous
    # length-only path no longer flips `overall` to True. (M-W-05)
    overall = (
        signature_verified
        and attestation_fresh
        and nonce_unique
        and model_in_registry
    )

    return VerificationResult(
        signature_well_formed=sig_well_formed,
        signature_verified=signature_verified,
        attestation_fresh=attestation_fresh,
        nonce_unique=nonce_unique,
        model_in_registry=model_in_registry,
        overall=overall,
    )
