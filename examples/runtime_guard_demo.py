import time
import random

from gvai.runtime_guard import GVRuntimeGuard, RuntimeSignals


def print_status(result: dict) -> None:
    gv = result["gv"]
    band = result["band"].upper()
    action = result["recommended_action"]

    bar_len = int(gv)
    bar = "█" * bar_len + "-" * (100 - bar_len)

    print(f"GV [{bar}] {gv:6.2f}  |  {band:<6}  |  action: {action}")


def main() -> None:
    guard = GVRuntimeGuard()

    print("\nStarting simulated agent loop…\n")

    # Phase 1 — normal behavior
    print("Phase 1: normal operation\n")
    for _ in range(5):
        signals = RuntimeSignals(
            token_delta=random.randint(50, 120),
            tool_calls_delta=random.randint(0, 1),
            error_delta=0,
            repeated_action_delta=0,
            recursion_depth=0,
        )
        result = guard.step(signals)
        print_status(result)
        time.sleep(0.5)

    # Phase 2 — degradation / thrash
    print("\nPhase 2: escalating instability\n")
    for _ in range(6):
        signals = RuntimeSignals(
            token_delta=random.randint(400, 900),
            tool_calls_delta=random.randint(2, 4),
            error_delta=random.randint(0, 1),
            repeated_action_delta=random.randint(1, 3),
            recursion_depth=random.randint(1, 3),
        )
        result = guard.step(signals)
        print_status(result)
        time.sleep(0.5)

    # Phase 3 — runaway
    print("\nPhase 3: runaway behavior\n")
    for _ in range(6):
        signals = RuntimeSignals(
            token_delta=random.randint(900, 1500),
            tool_calls_delta=random.randint(4, 7),
            error_delta=random.randint(1, 2),
            repeated_action_delta=random.randint(3, 6),
            recursion_depth=random.randint(3, 6),
        )
        result = guard.step(signals)
        print_status(result)
        time.sleep(0.5)

    print("\nSimulation complete.\n")


if __name__ == "__main__":
    main()
