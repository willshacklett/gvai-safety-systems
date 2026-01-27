from gvai import Sentinel


def main():
    sentinel = Sentinel(system_id="demo-agent", constraint_strength=0.8)

    result = sentinel.evaluate(
        {
            "uncertainty": 0.61,
            "drift": 0.19,
            "policy_pressure": 0.73,
        }
    )

    print("GV Sentinel Demo")
    print("System:", result["system_id"])
    print("GV Score:", result["gv_score"])
    print("Risk Band:", result["risk_band"])
    print("Actions:", result["actions"])
    print("Signals:", result["signals"])
    print("Timestamp:", result["timestamp"])


if __name__ == "__main__":
    main()
