"""Developer-facing gate in front of an existing DCL Trust Oracle.

Ask the Oracle whether an HTTP side effect may run. Execute the call only
when the verdict is COMMIT. Timeouts, malformed replies, server errors, and
unpaid checks fail closed.
"""

from dcl.guard import DCLGuard, Decision, OracleTrustConfig, SideEffectResult, request_digest
from dcl.sandbox import LocalSandbox

__all__ = [
    "DCLGuard",
    "Decision",
    "LocalSandbox",
    "OracleTrustConfig",
    "SideEffectResult",
    "request_digest",
]
