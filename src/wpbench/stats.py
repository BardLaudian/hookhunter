"""Bootstrap confidence intervals paired by case (docs/SPEC.md section 5). Standard library only."""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence

Interval = tuple[float, float]


def mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else float("nan")


def percentile(sorted_xs: Sequence[float], q: float) -> float:
    if not sorted_xs:
        return float("nan")
    pos = q * (len(sorted_xs) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_xs) - 1)
    return sorted_xs[lo] + (sorted_xs[hi] - sorted_xs[lo]) * (pos - lo)


def bootstrap_mean(per_case: Mapping[str, float], n: int = 10_000, seed: int = 20261101, alpha: float = 0.05) -> Interval:
    """Percentile CI of the mean over cases (resampling cases with replacement)."""
    values = list(per_case.values())
    if not values:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    k = len(values)
    means = sorted(mean([values[rng.randrange(k)] for _ in range(k)]) for _ in range(n))
    return percentile(means, alpha / 2), percentile(means, 1 - alpha / 2)


def bootstrap_diff(a: Mapping[str, float], b: Mapping[str, float], n: int = 10_000, seed: int = 20261101, alpha: float = 0.05) -> tuple[float, Interval, int]:
    """mean(a) - mean(b) over the cases both conditions have, resampling those cases together. Returns (diff, CI, cases)."""
    common = sorted(set(a) & set(b))
    if not common:
        return float("nan"), (float("nan"), float("nan")), 0
    d = [a[c] - b[c] for c in common]
    return mean(d), bootstrap_mean({str(i): x for i, x in enumerate(d)}, n, seed, alpha), len(common)
