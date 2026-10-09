from __future__ import annotations


def is_canonical_domain(domain: str) -> bool:
    try:
        encoded = domain.encode("ascii")
    except UnicodeEncodeError:
        return False
    if not encoded or len(encoded) > 253 or encoded.endswith(b"."):
        return False
    for label in encoded.split(b"."):
        if not 1 <= len(label) <= 63 or label.startswith(b"-") or label.endswith(b"-"):
            return False
        if any(not (97 <= value <= 122 or 48 <= value <= 57 or value == 45) for value in label):
            return False
    return True
