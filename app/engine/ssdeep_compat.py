"""
Pure-Python implementation of Context Triggered Piecewise Hashing (CTPH) / ssdeep fuzzy hash.
Standard base64 alphabet used by ssdeep.
"""
import math

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ROLLING_WINDOW = 7

class RollingHash:
    def __init__(self):
        self.h1 = 0
        self.h2 = 0
        self.h3 = 0
        self.window = [0] * ROLLING_WINDOW
        self.n = 0

    def roll_hash(self, c: int):
        self.h2 -= self.h1
        self.h2 += ROLLING_WINDOW * c
        self.h1 += c
        self.h1 -= self.window[self.n % ROLLING_WINDOW]
        self.window[self.n % ROLLING_WINDOW] = c
        self.n += 1
        self.h3 = (self.h3 << 5) & 0xFFFFFFFF
        self.h3 ^= c

    def sum(self) -> int:
        return (self.h1 + self.h2 + self.h3) & 0xFFFFFFFF


def fnv_hash(data: bytes, initial: int = 0x2802) -> int:
    h = initial
    for b in data:
        h = (h * 16777619) ^ b
        h &= 0xFFFFFFFF
    return h


def compute_ssdeep(data: bytes) -> str:
    """Computes a valid ssdeep-compatible fuzzy hash for the given bytes."""
    length = len(data)
    if length == 0:
        return "3::"

    # Determine base block size
    min_blocksize = 3
    blocksize = min_blocksize
    while blocksize * 64 < length:
        blocksize *= 2

    def hash_for_blocksize(bs: int) -> str:
        r = RollingHash()
        h_chunk1 = 0x2802
        h_chunk2 = 0x2802
        part1 = []
        part2 = []

        for b in data:
            r.roll_hash(b)
            h_chunk1 = ((h_chunk1 * 16777619) ^ b) & 0xFFFFFFFF
            h_chunk2 = ((h_chunk2 * 16777619) ^ b) & 0xFFFFFFFF

            if (r.sum() % bs) == (bs - 1):
                part1.append(B64[h_chunk1 % 64])
                h_chunk1 = 0x2802

            if (r.sum() % (bs * 2)) == ((bs * 2) - 1):
                part2.append(B64[h_chunk2 % 64])
                h_chunk2 = 0x2802

        part1.append(B64[h_chunk1 % 64])
        part2.append(B64[h_chunk2 % 64])

        return "".join(part1[:64]) + ":" + "".join(part2[:32])

    block_str = hash_for_blocksize(blocksize)
    return f"{blocksize}:{block_str}"


def ssdeep_similarity(hash1: str, hash2: str) -> int:
    """Calculates similarity score 0-100 between two ssdeep hashes."""
    try:
        b1, s1_1, s1_2 = hash1.split(":")
        b2, s2_1, s2_2 = hash2.split(":")
        b1, b2 = int(b1), int(b2)
    except Exception:
        return 0

    if b1 == b2:
        return _string_similarity(s1_1, s2_1)
    elif b1 * 2 == b2:
        return _string_similarity(s1_2, s2_1)
    elif b2 * 2 == b1:
        return _string_similarity(s1_1, s2_2)
    return 0


def _string_similarity(s1: str, s2: str) -> int:
    if not s1 or not s2:
        return 0
    # Levenshtein-based similarity
    len1, len2 = len(s1), len(s2)
    matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1):
        matrix[i][0] = i
    for j in range(len2 + 1):
        matrix[0][j] = j
    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            matrix[i][j] = min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost)
    dist = matrix[len1][len2]
    max_len = max(len1, len2)
    if max_len == 0:
        return 100
    score = int((1.0 - (dist / max_len)) * 100)
    return max(0, score)
