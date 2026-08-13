"""Typosquatting detection module."""

from __future__ import annotations

from dataclasses import dataclass

# Well-known brands for typosquat detection
KNOWN_BRANDS = {
    "google": ["gooogle", "gogle", "googIe", "g00gle", "goog1e"],
    "microsoft": ["microsft", "micros0ft", "micosoft", "rnicrosoft"],
    "apple": ["aple", "app1e", "applle"],
    "amazon": ["amaz0n", "amazzon", "arnazon"],
    "facebook": ["faceb00k", "faceboook", "facbook"],
    "paypal": ["paypa1", "paypall", "paypaI", "paaypal"],
    "netflix": ["netfl1x", "netfIix", "nettflix"],
    "instagram": ["instagrarn", "instagran", "instagrarn"],
    "twitter": ["twiter", "twittter", "tw1tter"],
    "linkedin": ["linkedln", "linked-in", "linkediin"],
    "github": ["githuub", "githb", "githu6"],
    "dropbox": ["dropbx", "drobpox", "dropboxx"],
    "chase": ["chasee", "chase-bank", "chasebank"],
    "wellsfargo": ["wellsfarg0", "wellsfarqo"],
    "bankofamerica": ["bankofamericaa", "bankofamerca"],
}


@dataclass
class TyposquatResult:
    possible_typosquat: bool
    confidence: str  # low | medium | high
    matched_brand: str | None
    reason: str | None


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(
                prev[j + 1] + 1,
                curr[j] + 1,
                prev[j] + (c1 != c2),
            ))
        prev = curr
    return prev[-1]


def _char_substitution_score(domain: str, brand: str) -> float:
    """Score similarity using character substitution patterns."""
    substitutions = {
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
        "7": "t", "8": "b", "9": "g", "l": "1", "o": "0",
        "i": "1", "rn": "m",
    }
    normalized = domain.lower()
    for sub, orig in substitutions.items():
        normalized = normalized.replace(sub, orig)
    distance = _levenshtein(normalized, brand)
    max_len = max(len(normalized), len(brand))
    if max_len == 0:
        return 0.0
    return 1.0 - (distance / max_len)


def detect_typosquat(domain: str) -> TyposquatResult:
    """Detect potential typosquatting of well-known brands."""
    # Extract the domain label (without TLD)
    parts = domain.lower().split(".")
    if len(parts) < 2:
        label = parts[0]
    else:
        label = parts[-2] if parts[-1] not in ("co", "com", "org", "net") else parts[-2]

    for brand, variants in KNOWN_BRANDS.items():
        # Direct variant match
        if label in variants:
            return TyposquatResult(
                possible_typosquat=True,
                confidence="high",
                matched_brand=brand,
                reason=f"Domain label '{label}' matches known typosquat variant of '{brand}'",
            )

        # Levenshtein distance check
        distance = _levenshtein(label, brand)
        if 0 < distance <= 2 and len(label) >= 4:
            confidence = "high" if distance == 1 else "medium"
            return TyposquatResult(
                possible_typosquat=True,
                confidence=confidence,
                matched_brand=brand,
                reason=f"Domain '{label}' is {distance} character(s) from '{brand}'",
            )

        # Character substitution
        score = _char_substitution_score(label, brand)
        if score >= 0.75 and label != brand:
            return TyposquatResult(
                possible_typosquat=True,
                confidence="medium" if score >= 0.85 else "low",
                matched_brand=brand,
                reason=f"Domain '{label}' appears similar to '{brand}' (similarity: {score:.0%})",
            )

    return TyposquatResult(
        possible_typosquat=False,
        confidence="low",
        matched_brand=None,
        reason=None,
    )
