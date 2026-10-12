"""Shannon entropy computation for raw byte sequences."""

import math
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (in bits, range [0.0, 8.0]) for a byte sequence.

    Args:
        data: Raw byte array to calculate entropy over.

    Returns:
        Shannon entropy in bits [0.0, 8.0]. Empty byte sequence returns 0.0.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return float(entropy)
