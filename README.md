# orogen-sdk (Python)

Python SDK for the Orogen. Drop-in OpenAI client + automatic nonce generation (RFC-0007) + optional receipt verification (RFC-0001).

## Install

```bash
uv add orogen-sdk
# or
pip install orogen-sdk
```

## Quick start

```python
from orogen_sdk import OrogenClient

with OrogenClient(api_key="orog_...", base_url="https://gateway.orogen.network/v1") as client:
    response = client.chat.completions.create(
        model="llama-3.1-70b-instruct@my-adapter",
        messages=[{"role": "user", "content": "Hello!"}],
        useful_verify_receipt=True,
    )
    print(response.choices[0]["message"]["content"])
    print(response.useful_verification.summary)  # "verified"
```

## Extensions over OpenAI

| Param | Purpose |
|---|---|
| `useful_nonce` | Override auto-generated nonce (RFC-0007) |
| `useful_tier` | Preferred operator tier (dc-premium, dc-standard, ...) |
| `useful_region` | Preferred geo region for latency |
| `useful_max_price_per_million` | Cap CUC per million tokens |
| `useful_verify_receipt` | Verify response receipt client-side |

The response includes `.useful_receipt` (the operator-signed receipt) and, when verification is requested, `.useful_verification` (a `VerificationResult`).

## Development

```bash
uv sync
uv run pytest
uv run ruff check
uv run mypy src
```

## Interop notes

The SDK is deliberately liberal about field naming to interoperate with the gateway-router reference implementation:

- **Receipt envelope** — accepts either `useful_receipt` (canonical) or `receipt` (gateway-internal).
- **Nonce field** — sends both `useful_nonce` (canonical) and `customer_nonce` (gateway-internal) in the request body.
- **`created` field** — defaults to 0 if the gateway omits the OpenAI-standard timestamp.
- **`log_probs_sample`** — accepts both base64-string (RFC-0001 canonical) and raw list[float] (gateway-internal).

**Nonce flow:** the canonical RFC-0007 has the customer generating nonces. The reference gateway issues nonces via `POST /v1/nonces` and rejects customer-generated ones. The SDK supports both modes:

```python
# Customer-generated mode (RFC-0007 canonical, default)
client = OrogenClient(api_key="...", base_url="...")
# nonce is auto-generated on each request

# Gateway-issued mode (reference gateway-router)
client = OrogenClient(api_key="...", base_url="...", nonce_mode="gateway-issued")
# SDK auto-calls POST /nonces before each request

# Manual fetch (either mode)
nonce = client.fetch_nonce()
client.chat.completions.create(..., useful_nonce=nonce)
```

DECISIONS.md H15 tracks the eventual contract alignment.

## Compliance

Cryptographic signature verification on the client is best-effort (it requires the operator hotkey, which the client doesn't have). Authoritative verification is performed on-chain by validators per RFC-0006 sampling.
