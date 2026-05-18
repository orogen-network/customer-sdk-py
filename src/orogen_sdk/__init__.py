"""Python SDK for the Orogen.

Drop-in replacement for the OpenAI client. Routes inference requests through
the network's gateway, which burns OROG → mints CUC credit → settles to
operators. The SDK auto-generates nonces (RFC-0007) and verifies signed
response receipts (RFC-0001).

Example:
    from orogen_sdk import OrogenClient
    client = OrogenClient(api_key="orog_...", base_url="https://gateway.orogen.network/v1")
    response = client.chat.completions.create(
        model="llama-3.1-70b-instruct@my-adapter",
        messages=[{"role": "user", "content": "hello"}],
    )
"""

from orogen_sdk.client import OrogenClient
from orogen_sdk.nonce import generate_nonce
from orogen_sdk.types import (
    AttestationReport,
    Receipt,
    VerificationResult,
)
from orogen_sdk.verify import verify_receipt

__all__ = [
    "OrogenClient",
    "Receipt",
    "AttestationReport",
    "VerificationResult",
    "generate_nonce",
    "verify_receipt",
]
__version__ = "0.1.0"
