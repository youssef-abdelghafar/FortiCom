"""Data sources. Swap the dataset by changing one call (synthetic -> load_csv)."""
import csv
import numpy as np


def synthetic(steps=600, n=5, seed=0):
    """Correlated in-situ sensors (e.g. soil moisture): shared latent signal
    + per-sensor offset + noise. Neighbours agree, which enables cross-validation."""
    rng = np.random.default_rng(seed)
    t = np.arange(steps)
    phase = rng.uniform(0, 6.28)
    common = 0.30 + 0.05 * np.sin(2 * np.pi * t / 200) + 0.02 * np.sin(2 * np.pi * t / 370 + phase)
    offsets = rng.normal(0, 0.01, n)
    noise = rng.normal(0, 0.004, (steps, n))
    return common[:, None] + offsets[None, :] + noise


def load_csv(path, n=5, max_rows=None):
    """Wide CSV: each numeric column = one sensor (time-aligned). Takes the first n numeric columns."""
    rows = []
    with open(path, newline="") as f:
        for r in csv.reader(f):
            try:
                rows.append([float(x) for x in r])
            except ValueError:
                continue  # header or bad line
            if max_rows and len(rows) >= max_rows:
                break
    arr = np.array(rows)
    return arr[:, :n]
