"""RFC-0007 nonce generation.

256-bit random nonce per inference. The customer signs `(nonce, timestamp, customer_signature)`
and the gateway rejects duplicates within 24h at the (operator, nonce) tuple level.
"""

from __future__ import annotations

import secrets
import time


def generate_nonce() -> str:
    """Return a fresh 256-bit nonce as 0x-prefixed hex string."""
    return "0x" + secrets.token_hex(32)


def current_timestamp_ms() -> int:
    """Return the current Unix epoch in milliseconds."""
    return int(time.time() * 1000)
