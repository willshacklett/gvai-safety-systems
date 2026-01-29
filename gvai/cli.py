from __future__ import annotations

import json
import sys

from .guard import GVRuntimeGuard, GuardConfig
from .signals import RuntimeSignals


def main() -> None:
    """
    Read RuntimeSignals JSON from stdin and output a GV guard decision as JSON.

    Example:
      echo '{"token_delta":120,"tool_calls_delta":1,"error_delta":0,"repeated_action_delta":0,"recursion_depth":0}' | python -m gvai.runtime_guard.cli
    """
    raw = sys.stdin.read().strip()
    if not raw:
        print("Expected JSON on stdin.", file=sys.stderr)
        sys.exit(2)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print("Invalid JSON.", file=sys.stderr)
        sys.exit(2)

    guard = GVRuntimeGuard(GuardConfig())
    signals = RuntimeSignals(**data)
    out = guard.step(signals)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
