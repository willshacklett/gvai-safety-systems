import numpy as np
import pandas as pd
from pathlib import Path

Path("data").mkdir(parents=True, exist_ok=True)

rng = np.random.default_rng(7)
n = 220
t = np.arange(n)

# Recoverable trace
x = 1.0 + 0.02 * rng.normal(size=n)
for i in range(40, 80):
    x[i] += 0.05 * np.exp(-(i - 40) / 10)

recoverable = pd.DataFrame({
    "t": t,
    "metric": x,
    "outcome": "recoverable",
})
recoverable.to_csv("data/sample_recoverable.csv", index=False)

# Irreversible trace
x2 = 1.0 + 0.02 * rng.normal(size=n)
for i in range(120, n):
    x2[i] += 0.02 * (i - 120)

irreversible = pd.DataFrame({
    "t": t,
    "metric": x2,
    "outcome": "irreversible",
})
irreversible.to_csv("data/sample_irreversible.csv", index=False)

print("Wrote:")
print(" - data/sample_recoverable.csv")
print(" - data/sample_irreversible.csv")
