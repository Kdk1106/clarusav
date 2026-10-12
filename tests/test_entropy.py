"""Unit tests for Shannon entropy computation and edge cases."""

import math
import os

from clarusav.features.entropy import calculate_entropy


def test_entropy_empty_bytes():
    """Empty byte sequence should return 0.0."""
    assert calculate_entropy(b"") == 0.0


def test_entropy_single_repeated_byte():
    """Homogeneous bytes have zero uncertainty (H = 0.0)."""
    assert calculate_entropy(b"\x00" * 1000) == 0.0
    assert calculate_entropy(b"A" * 500) == 0.0
    assert calculate_entropy(b"\xff") == 0.0


def test_entropy_two_equiprobable_bytes():
    """Two symbols with equal probability have H = -2 * (0.5 * log2(0.5)) = 1.0."""
    data = (b"A" * 500) + (b"B" * 500)
    ent = calculate_entropy(data)
    assert math.isclose(ent, 1.0, rel_tol=1e-6)


def test_entropy_four_equiprobable_bytes():
    """Four symbols with equal probability have H = 2.0."""
    data = (b"A" * 250) + (b"B" * 250) + (b"C" * 250) + (b"D" * 250)
    ent = calculate_entropy(data)
    assert math.isclose(ent, 2.0, rel_tol=1e-6)


def test_entropy_eight_equiprobable_bytes():
    """Eight symbols with equal probability have H = 3.0."""
    data = b"".join(bytes([i]) * 100 for i in range(8))
    ent = calculate_entropy(data)
    assert math.isclose(ent, 3.0, rel_tol=1e-6)


def test_entropy_maximum_256_uniform_bytes():
    """Uniform distribution over all 256 byte values achieves theoretical max H = 8.0."""
    data = bytes(range(256)) * 20
    ent = calculate_entropy(data)
    assert math.isclose(ent, 8.0, rel_tol=1e-6)


def test_entropy_random_bytes():
    """Cryptographic pseudo-random bytes should have high entropy near 8.0."""
    random_data = os.urandom(8192)
    ent = calculate_entropy(random_data)
    assert ent > 7.9


def test_entropy_monotonic_property():
    """Adding randomness to repetitive data must monotonically increase entropy."""
    data_low = b"A" * 1000
    data_mid = (b"A" * 900) + (b"B" * 100)
    data_high = (b"A" * 500) + (b"B" * 500)

    ent_low = calculate_entropy(data_low)
    ent_mid = calculate_entropy(data_mid)
    ent_high = calculate_entropy(data_high)

    assert ent_low < ent_mid < ent_high
