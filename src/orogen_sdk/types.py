"""Pydantic data models matching RFC-0001 (receipt), RFC-0002 (attestation), RFC-0007 (nonce)."""

from __future__ import annotations

from typing import Any, Literal

import json

from pydantic import AliasChoices, BaseModel, Field


class KvMetadata(BaseModel):
    """RFC-0001 §KvMetadata."""

    prefix_hint: str | None = None  # 0x-prefixed H256
    cache_hit: bool = False
    kv_blocks_used: int = 0


class Receipt(BaseModel):
    """RFC-0001 §Receipt — operator-signed response receipt."""

    version: int = 1
    job_id: str  # 0x-prefixed H256
    operator_id: str  # SS58 or 0x-prefixed AccountId
    model_id: str
    model_weight_hash: str
    adapter_id: str | None = None
    customer_nonce: str
    request_hash: str
    response_hash: str
    # Per RFC-0001 canonical form is base64; some implementations emit a list of floats
    # (raw log-probs). Accept both.
    log_probs_sample: str | list[float] = Field(description="base64 of bounded vec or raw list[f]")
    kv_metadata: KvMetadata
    kernel_pack_hash: str
    gpu_model: str
    driver_version: str
    cuda_version: str
    attestation_report_hash: str
    batch_invariant_proof: str | None = None
    timestamp_ms: int
    gateway_id: str
    operator_signature: str  # hex ed25519 (128 chars)

    def signing_payload(self) -> bytes:
        """Canonical bytes that were signed by the operator.

        Mirrors the `mining_types.Receipt.signing_payload` contract used by
        the rest of the stack: stable JSON of the receipt model dump with
        `operator_signature` removed.
        """
        d = self.model_dump(mode="json")
        d.pop("operator_signature", None)
        return json.dumps(
            d, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str,
        ).encode("utf-8")


class AttestationReport(BaseModel):
    """RFC-0002 §AttestationReport — combined multi-vendor TEE attestation."""

    version: int = 1
    operator_id: str
    tier: Literal["dc-premium", "dc-standard", "cloud-rented", "prosumer", "edge", "embed-only", "compliance"]
    gpu_quote: dict[str, Any] | None = None  # NvidiaQuote
    tdx_quote: dict[str, Any] | None = None  # IntelTdxQuote
    sev_snp_report: dict[str, Any] | None = None  # AmdSevSnpReport
    rim_attestation: dict[str, Any] | None = None  # NvtrustRimAttestation
    firmware_hashes: list[str] = []
    measured_vm_bundle: str
    timestamp_ms: int
    validity_window_ms: int
    aggregator_signature: str  # base64
    vendor_pki_chain_hashes: list[str] = []


class VerificationResult(BaseModel):
    """Output of verify_receipt — what we could verify against the receipt.

    Security audit M-W-05 / M-W-08
    ------------------------------
    `signature_well_formed` is purely a shape check (length, base64/hex).
    `signature_verified` is True only if the caller passed an
    `operator_pubkey_hex` to `verify_receipt` AND a real ed25519
    verification against `receipt.signing_payload()` succeeded.
    `overall` requires `signature_verified is True` — a forged signature
    of the right length is no longer accepted.

    The previous `tier_matches` field has been removed because it was a
    no-op constant (always True). Tier comparison belongs in the linked
    attestation report (RFC-0002), which is fetched separately.
    """

    signature_well_formed: bool
    signature_verified: bool
    attestation_fresh: bool
    nonce_unique: bool
    model_in_registry: bool
    overall: bool

    @property
    def summary(self) -> str:
        if self.overall:
            return "verified"
        failures = [k for k, v in self.model_dump().items() if v is False and k != "overall"]
        return f"failed: {', '.join(failures)}"


class ChatRequest(BaseModel):
    """OpenAI-compatible chat completion request, with our extensions."""

    model: str
    messages: list[dict[str, Any]]
    temperature: float | None = None
    max_tokens: int | None = None
    stream: bool = False
    seed: int | None = None
    # Our extensions:
    useful_nonce: str | None = Field(default=None, description="RFC-0007 nonce; auto-generated if omitted")
    useful_tier: str | None = Field(default=None, description="Preferred operator tier")
    useful_region: str | None = Field(default=None, description="Preferred geo region")
    useful_max_price_per_million: int | None = Field(default=None, description="Max CUC price per million tokens")
    useful_verify_receipt: bool = Field(default=False, description="If true, verify receipt before returning")


class ChatResponse(BaseModel):
    """OpenAI-compatible response augmented with our receipt + verification."""

    model_config = {"populate_by_name": True}

    id: str
    object: Literal["chat.completion"] = "chat.completion"
    created: int = Field(default_factory=lambda: 0, description="unix seconds; some gateways omit")
    model: str = ""
    choices: list[dict[str, Any]]
    usage: dict[str, int] = Field(default_factory=dict)
    # Our extensions — accept either `useful_receipt` (canonical) or `receipt` (gateway-internal).
    useful_receipt: Receipt | None = Field(
        default=None,
        validation_alias=AliasChoices("useful_receipt", "receipt"),
    )
    useful_verification: VerificationResult | None = None
