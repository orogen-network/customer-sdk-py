"""OrogenClient — OpenAI-compatible client routing through the Orogen gateway."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import httpx

from orogen_sdk.nonce import current_timestamp_ms, generate_nonce
from orogen_sdk.types import ChatRequest, ChatResponse
from orogen_sdk.verify import verify_receipt


class _ChatNamespace:
    def __init__(self, client: OrogenClient) -> None:
        self._client = client
        self.completions = _ChatCompletions(client)


class _ChatCompletions:
    def __init__(self, client: OrogenClient) -> None:
        self._client = client

    def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream: bool = False,
        seed: int | None = None,
        useful_nonce: str | None = None,
        useful_tier: str | None = None,
        useful_region: str | None = None,
        useful_max_price_per_million: int | None = None,
        useful_verify_receipt: bool = False,
        useful_operator_pubkey_hex: str | None = None,
        **extra: Any,
    ) -> ChatResponse:
        if useful_nonce is not None:
            nonce = useful_nonce
        elif self._client.nonce_mode == "gateway-issued":
            nonce = self._client.fetch_nonce()
        else:
            nonce = generate_nonce()
        request = ChatRequest(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=stream,
            seed=seed,
            useful_nonce=nonce,
            useful_tier=useful_tier,
            useful_region=useful_region,
            useful_max_price_per_million=useful_max_price_per_million,
            useful_verify_receipt=useful_verify_receipt,
        )

        headers = {
            "Authorization": f"Bearer {self._client.api_key}",
            "x-useful-nonce": nonce,
            "x-useful-nonce-ts-ms": str(current_timestamp_ms()),
        }
        if useful_tier:
            headers["x-useful-tier"] = useful_tier
        if useful_region:
            headers["x-useful-region"] = useful_region

        url = f"{self._client.base_url.rstrip('/')}/chat/completions"
        body = request.model_dump(exclude_none=True, by_alias=False)
        # Security audit M-W-06: only send `customer_nonce` on the wire.
        # The previous code aliased the same value under both `useful_nonce`
        # and `customer_nonce` "for max compatibility", which let a gateway
        # that honoured only one of the two see a replayed body as fresh if
        # the *other* field was flipped. The canonical field is
        # `customer_nonce` per RFC-0007.
        body.pop("useful_nonce", None)
        body["customer_nonce"] = nonce
        resp = self._client.http.post(url, json=body, headers=headers, timeout=self._client.timeout)
        resp.raise_for_status()
        data = resp.json()

        chat = ChatResponse(**data)

        if useful_verify_receipt and chat.useful_receipt is not None:
            chat.useful_verification = verify_receipt(
                chat.useful_receipt,
                operator_pubkey_hex=useful_operator_pubkey_hex,
                expected_nonce=nonce,
            )
        return chat


class OrogenClient:
    """OpenAI-compatible client for the Orogen.

    Args:
        api_key: bearer token from the gateway (or pre-TGE custodial credit).
        base_url: gateway base URL, e.g. https://gateway.orogen.network/v1
        timeout: request timeout in seconds.
        http: optional pre-configured httpx.Client for testing.
        nonce_mode: "gateway-issued" (gateway issues via POST /nonces; SDK auto-fetches
            before each chat completion) or "customer" (customer generates). Default
            "gateway-issued" to interoperate with gateways that require issued
            nonces.
    """

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = "https://gateway.orogen.network/v1",
        timeout: float = 60.0,
        http: httpx.Client | None = None,
        nonce_mode: str = "gateway-issued",
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.http = http or httpx.Client()
        if nonce_mode not in {"gateway-issued", "customer"}:
            raise ValueError("nonce_mode must be 'gateway-issued' or 'customer'")
        self.nonce_mode = nonce_mode
        self.chat = _ChatNamespace(self)

    def fetch_nonce(self) -> str:
        """Request a gateway-issued nonce via POST /nonces.

        Used by `gateway-issued` mode. Caller can also call directly to
        pre-allocate a nonce, then pass it as `useful_nonce`.
        """
        url = f"{self.base_url.rstrip('/')}/nonces"
        resp = self.http.post(
            url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return str(resp.json()["nonce"])

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> OrogenClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def canonical_request_hash(messages: list[dict[str, Any]]) -> str:
    """RFC-0001 request_hash: SHA-256 over canonical JSON of messages."""
    payload = json.dumps(messages, sort_keys=True, separators=(",", ":")).encode()
    return "0x" + hashlib.sha256(payload).hexdigest()
