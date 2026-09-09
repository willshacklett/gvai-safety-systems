from __future__ import annotations

from gvai.sentinel import GVSentinel


def state_to_nodes(stress: float):
    return [
        1.0,
        1.0 + stress,
        max(0.0, 1.0 - stress),
        1.0,
    ]


def main():
    sentinel = GVSentinel()

    stress = 0.0

    print(
        f"{'STEP':>4} | "
        f"{'STRESS':>7} | "
        f"{'STATUS':>12} | "
        f"{'RECOV':>7} | "
        f"{'VAR':>8} | "
        f"{'VEL':>8} | "
        f"{'ACCEL':>8} | "
        f"{'DT':>10} | "
        f"{'ACTION':>10}"
    )

    print("-" * 105)

    for step in range(30):
        observation = sentinel.update(
            node_values=state_to_nodes(stress)
        )

        dt = observation.delta_t_estimate

        print(
            f"{step:>4} | "
            f"{stress:>7.3f} | "
            f"{observation.status:>12} | "
            f"{observation.recoverability_score:>7.3f} | "
            f"{observation.variance_value:>8.4f} | "
            f"{observation.variance_velocity:>8.4f} | "
            f"{observation.variance_acceleration:>8.4f} | "
            f"{str(round(dt, 3) if dt is not None else None):>10} | "
            f"{observation.recommended_action:>10}"
        )

        # Constant deterioration: no sudden acceleration.
        stress += 0.12


if __name__ == "__main__":
    main()
