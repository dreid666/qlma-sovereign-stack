from __future__ import annotations

import base64
import binascii
import math
import string
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional


ENGLISH_FREQ = {
    "A": 0.08167, "B": 0.01492, "C": 0.02782, "D": 0.04253,
    "E": 0.12702, "F": 0.02228, "G": 0.02015, "H": 0.06094,
    "I": 0.06966, "J": 0.00153, "K": 0.00772, "L": 0.04025,
    "M": 0.02406, "N": 0.06749, "O": 0.07507, "P": 0.01929,
    "Q": 0.00095, "R": 0.05987, "S": 0.06327, "T": 0.09056,
    "U": 0.02758, "V": 0.00978, "W": 0.02360, "X": 0.00150,
    "Y": 0.01974, "Z": 0.00074,
}

COMMON_QUADGRAMS = {
    "TION": -2.18, "NTHE": -2.31, "THER": -2.39, "THAT": -2.43,
    "OFTH": -2.45, "FTHE": -2.48, "THES": -2.52, "WITH": -2.57,
    "INTH": -2.61, "ATIO": -2.68, "OTHE": -2.70, "TTHE": -2.72,
    "DTHE": -2.73, "STHE": -2.74, "HERE": -2.77, "ETHE": -2.79,
    "SAND": -2.82, "EDTO": -2.85, "TOBE": -2.88, "ANDT": -2.91,
}
FLOOR_LOG_PROB = -7.5

MORSE_DICT = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9", ".-.-.-": ".",
    "--..--": ",", "..--..": "?",
}


@dataclass
class SolverCandidate:
    method: str
    key: Any
    plaintext: str
    score: float
    ioc: float
    entropy: float
    trail: list[str] = field(default_factory=list)


class DecryptionEngineSolver:
    @staticmethod
    def shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        n = len(text)
        counts = Counter(text)
        return -sum((count / n) * math.log2(count / n)
                    for count in counts.values())

    @staticmethod
    def index_of_coincidence(text: str) -> float:
        letters = [ch.upper() for ch in text
                   if ch.isascii() and ch.isalpha()]
        n = len(letters)
        if n <= 1:
            return 0.0
        counts = Counter(letters)
        return sum(count * (count - 1) for count in counts.values()) / (n * (n - 1))

    @staticmethod
    def chi_squared(text: str) -> float:
        letters = [ch.upper() for ch in text
                   if ch.isascii() and ch.isalpha()]
        n = len(letters)
        if n == 0:
            return float("inf")
        counts = Counter(letters)
        return sum(((counts.get(ch, 0) - n * prob) ** 2) / (n * prob + 1e-6)
                   for ch, prob in ENGLISH_FREQ.items())

    @classmethod
    def quadgram_avg(cls, text: str) -> float:
        letters = "".join(ch.upper() for ch in text
                          if ch.isascii() and ch.isalpha())
        if len(letters) < 4:
            return FLOOR_LOG_PROB
        values = (COMMON_QUADGRAMS.get(letters[i:i + 4], FLOOR_LOG_PROB)
                  for i in range(len(letters) - 3))
        return sum(values) / (len(letters) - 3)

    @classmethod
    def fitness_score(cls, text: str) -> float:
        if not text:
            return -1e9
        printable_ratio = sum(ch in string.printable for ch in text) / len(text)
        if printable_ratio < 0.85:
            return -1e6 * (1.0 - printable_ratio)
        letters = "".join(ch.upper() for ch in text
                          if ch.isascii() and ch.isalpha())
        if len(letters) < 2:
            return -250.0
        chi_norm = cls.chi_squared(letters) / len(letters)
        return (-chi_norm * 6.0) + (cls.quadgram_avg(letters) * 5.0)

    @classmethod
    def make_candidate(cls, method: str, key: Any, text: str,
                       trail: Optional[list[str]] = None) -> SolverCandidate:
        trail = trail or []
        return SolverCandidate(method, key, text,
                               round(cls.fitness_score(text), 4),
                               round(cls.index_of_coincidence(text), 4),
                               round(cls.shannon_entropy(text), 4), list(trail))

    @classmethod
    def unwrap_encodings(cls, payload: str, max_depth: int = 4) -> tuple[str, list[str]]:
        if max_depth < 0:
            raise ValueError("max_depth must be non-negative")
        current = payload.strip()
        trail: list[str] = []

        for _ in range(max_depth):
            progressed = False

            if "%" in current:
                unquoted = urllib.parse.unquote(current)
                if unquoted != current:
                    current = unquoted
                    trail.append("URL")
                    progressed = True
                    continue

            compact = "".join(current.split())
            if (len(compact) >= 4 and len(compact) % 4 == 0
                    and all(ch in string.ascii_letters + string.digits + "+/-_="
                            for ch in compact)):
                try:
                    raw = base64.b64decode(compact, altchars=b"-_", validate=True)
                    decoded = raw.decode("utf-8")
                    if decoded and all(ch in string.printable for ch in decoded):
                        current = decoded
                        trail.append("Base64")
                        progressed = True
                        continue
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    pass

            hex_clean = "".join(current.split())
            if (len(hex_clean) >= 4 and len(hex_clean) % 2 == 0
                    and all(ch in string.hexdigits for ch in hex_clean)):
                try:
                    decoded = bytes.fromhex(hex_clean).decode("utf-8")
                    if decoded and all(ch in string.printable for ch in decoded):
                        current = decoded
                        trail.append("Hex")
                        progressed = True
                        continue
                except (ValueError, UnicodeDecodeError):
                    pass

            bin_clean = "".join(current.split())
            if (len(bin_clean) >= 8 and len(bin_clean) % 8 == 0
                    and all(ch in "01" for ch in bin_clean)):
                try:
                    decoded = bytes(int(bin_clean[i:i + 8], 2)
                                    for i in range(0, len(bin_clean), 8)).decode("utf-8")
                    if decoded and all(ch in string.printable for ch in decoded):
                        current = decoded
                        trail.append("Binary8")
                        progressed = True
                        continue
                except (ValueError, UnicodeDecodeError):
                    pass

            tokens = current.strip().split()
            if tokens and all(set(token).issubset(set("./-")) for token in tokens):
                unmapped: list[str] = []
                words: list[str] = []
                for word in current.strip().replace(" / ", "/").split("/"):
                    chars: list[str] = []
                    for token in word.split():
                        if token in MORSE_DICT:
                            chars.append(MORSE_DICT[token])
                        elif token:
                            unmapped.append(token)
                            chars.append(f"[{token}]")
                    if chars:
                        words.append("".join(chars))
                if words:
                    current = " ".join(words)
                    trail.append(f"Morse(unmapped={len(unmapped)})")
                    progressed = True
                    continue

            if not progressed:
                break

        return current, trail

    @staticmethod
    def caesar(text: str, shift: int, decrypt: bool = True) -> str:
        if not 0 <= shift <= 25:
            raise ValueError("shift must be between 0 and 25")
        eff = (-shift if decrypt else shift) % 26
        output = []
        for ch in text:
            if "a" <= ch <= "z":
                output.append(chr((ord(ch) - 97 + eff) % 26 + 97))
            elif "A" <= ch <= "Z":
                output.append(chr((ord(ch) - 65 + eff) % 26 + 65))
            else:
                output.append(ch)
        return "".join(output)

    @staticmethod
    def atbash(text: str) -> str:
        output = []
        for ch in text:
            if "a" <= ch <= "z":
                output.append(chr(122 - (ord(ch) - 97)))
            elif "A" <= ch <= "Z":
                output.append(chr(90 - (ord(ch) - 65)))
            else:
                output.append(ch)
        return "".join(output)

    @classmethod
    def vigenere(cls, text: str, key: str, decrypt: bool = True) -> str:
        shifts = [ord(ch.upper()) - 65 for ch in key
                  if ch.isascii() and ch.isalpha()]
        if not shifts:
            return text
        output = []
        index = 0
        for ch in text:
            if ch.isascii() and ch.isalpha():
                eff = (-shifts[index % len(shifts)] if decrypt
                       else shifts[index % len(shifts)])
                base = 65 if ch.isupper() else 97
                output.append(chr((ord(ch) - base + eff) % 26 + base))
                index += 1
            else:
                output.append(ch)
        return "".join(output)

    @classmethod
    def vigenere_auto_crack(cls, text: str, max_key_len: int = 12) -> tuple[str, str]:
        clean = "".join(ch.upper() for ch in text
                        if ch.isascii() and ch.isalpha())
        if len(clean) < 16:
            return "", text
        upper = min(max_key_len, len(clean) // 2)
        if upper < 1:
            return "", text

        best_len = 1
        best_ioc = -1.0
        for key_len in range(1, upper + 1):
            columns = [clean[i::key_len] for i in range(key_len)]
            avg_ioc = sum(cls.index_of_coincidence(column) for column in columns) / key_len
            if avg_ioc > best_ioc:
                best_ioc = avg_ioc
                best_len = key_len

        key_chars = []
        for i in range(best_len):
            column = clean[i::best_len]
            shift = min(range(26), key=lambda candidate:
                        cls.chi_squared(cls.caesar(column, candidate, True)))
            key_chars.append(chr(shift + 65))
        key = "".join(key_chars)
        return key, cls.vigenere(text, key, decrypt=True)

    @staticmethod
    def rail_fence_decrypt(text: str, rails: int) -> str:
        n = len(text)
        if rails <= 1 or rails >= n:
            return text
        pattern = [[False] * n for _ in range(rails)]
        row, step = 0, 1
        for col in range(n):
            pattern[row][col] = True
            if row == 0:
                step = 1
            elif row == rails - 1:
                step = -1
            row += step

        grid = [[""] * n for _ in range(rails)]
        index = 0
        for r in range(rails):
            for c in range(n):
                if pattern[r][c]:
                    if index >= n:
                        raise ValueError("invalid Rail Fence ciphertext")
                    grid[r][c] = text[index]
                    index += 1

        output = []
        row, step = 0, 1
        for col in range(n):
            output.append(grid[row][col])
            if row == 0:
                step = 1
            elif row == rails - 1:
                step = -1
            row += step
        return "".join(output)

    @classmethod
    def solve(cls, payload: str, top_k: int = 5) -> list[SolverCandidate]:
        if top_k < 1:
            raise ValueError("top_k must be positive")
        unwrapped, trail = cls.unwrap_encodings(payload)
        candidates = [
            cls.make_candidate("Raw/Unwrapped", trail[-1] if trail else "none", unwrapped, trail),
            cls.make_candidate("Atbash", "A<->Z", cls.atbash(unwrapped), trail + ["Atbash"]),
        ]
        for shift in range(26):
            candidates.append(cls.make_candidate(
                "Caesar", shift, cls.caesar(unwrapped, shift, True),
                trail + [f"Caesar({shift})"]))

        key, plain = cls.vigenere_auto_crack(unwrapped)
        if key:
            candidates.append(cls.make_candidate(
                "Vigenere-Auto", key, plain, trail + [f"Vigenere({key})"]))

        for rails in range(2, min(11, max(3, len(unwrapped)))):
            candidates.append(cls.make_candidate(
                "RailFence", rails, cls.rail_fence_decrypt(unwrapped, rails),
                trail + [f"RailFence({rails})"]))

        raw = unwrapped.encode("utf-8", errors="ignore")
        best_key = min(range(256), key=lambda key: cls.chi_squared(
            bytes(byte ^ key for byte in raw).decode("utf-8", errors="ignore")))
        plain_xor = bytes(byte ^ best_key for byte in raw).decode("utf-8", errors="ignore")
        candidates.append(cls.make_candidate(
            "SingleByteXOR", f"0x{best_key:02x}", plain_xor,
            trail + [f"XOR(0x{best_key:02x})"]))

        candidates.sort(key=lambda candidate: candidate.score, reverse=True)
        return candidates[:top_k]


if __name__ == "__main__":
    sample = "Khoor, zruog! Wklv lv d whvw phvvdjh."
    for rank, candidate in enumerate(DecryptionEngineSolver.solve(sample, 3), 1):
        print(f"#{rank} [{candidate.method} key={candidate.key} score={candidate.score} "
              f"IoC={candidate.ioc}] trail={' -> '.join(candidate.trail)} "
              f"=> {candidate.plaintext}")
