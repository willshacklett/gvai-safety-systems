"""Bounded local dependency check; never print response bodies or exceptions."""

import json
import sys
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener


def check_ready(attempts=5):
    opener = build_opener(ProxyHandler({}))
    for attempt in range(attempts):
        try:
            with opener.open("http://127.0.0.1:8080/readyz", timeout=3) as response:
                payload = response.read(1025)
                if (
                    response.status == 200 and len(payload) <= 1024
                    and json.loads(payload) == {
                        "status": "ready", "advisory_only": True, "enforcement_applied": False,
                    }
                ):
                    return 0
        except (URLError, OSError, ValueError):
            pass
        if attempt + 1 < attempts:
            time.sleep(1)
    print("GVAI private advisory readiness unavailable.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(check_ready())
