"""
dcl_core.seal — human-readable verification seal formatting.

Pure presentation over already-public fields (tx_hash, input_hash,
timestamp). No scoring/policy logic, no network call — mirrors
`formatSeal()` in @fronesis-labs/dcl-sdk (TypeScript) exactly, including
the white-label options, so other DCL-protocol implementers aren't stuck
with Fronesis Labs' branding.
"""

from datetime import datetime, timezone
from typing import TypedDict


class Seal(TypedDict):
    seal_text: str
    verify_url: str


DEFAULT_BRAND = "Leibniz Layer | Fronesis Labs"
DEFAULT_VERIFY_BASE_URL = "https://x402.fronesislabs.com/verify"
DEFAULT_NETWORK = "Base Mainnet"


def _strip_hex_prefix(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


def _format_sealed_timestamp(unix_seconds: float) -> str:
    return datetime.fromtimestamp(unix_seconds, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )


def format_seal(
    tx_hash: str,
    input_hash: str,
    timestamp: float,
    brand: str = DEFAULT_BRAND,
    verify_base_url: str = DEFAULT_VERIFY_BASE_URL,
    network: str = DEFAULT_NETWORK,
) -> Seal:
    """Formats a human-readable "Verified by..." seal.

    Does not fetch or verify anything itself — call verify_chain() /
    recompute_tx_hash() first if you want an integrity guarantee behind
    the seal you're displaying. Set network="" to omit the network suffix.
    """
    hash_display = _strip_hex_prefix(tx_hash)
    intent_display = _strip_hex_prefix(input_hash)
    sealed = _format_sealed_timestamp(timestamp)
    verify_url = f"{verify_base_url}/{hash_display}"
    network_suffix = f" — {network}" if network else ""

    seal_text = "\n".join(
        [
            f"🔒 Verified by {brand}",
            f"Hash: {hash_display}",
            f"Intent: {intent_display}",
            f"Sealed: {sealed}{network_suffix}",
            f"Verify: {verify_url}",
        ]
    )

    return {"seal_text": seal_text, "verify_url": verify_url}
