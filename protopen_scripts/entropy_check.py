#!/usr/bin/env python3
"""File entropy analyzer.

Calculates Shannon entropy of a file to estimate whether it contains
encrypted, packed, or compressed content typical of malicious payloads.
High entropy (>7.0) is a strong indicator of obfuscation.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import logging
from typing import Any
from collections import Counter

logger = logging.getLogger(__name__)

ENTROPY_THRESHOLDS = {
    "low": (0.0, 4.0),
    "moderate_compression": (4.0, 6.0),
    "high_compression": (6.0, 7.0),
    "likely_encrypted": (7.0, 7.5),
    "strongly_encrypted": (7.5, 8.0),
}


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes (0-8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _classify_entropy(entropy: float, file_ext: str) -> tuple[str, str]:
    """Return (label, description) for entropy value."""
    ext = file_ext.lower()

    # Known high-entropy file types (not suspicious)
    naturally_high = {'.zip', '.gz', '.xz', '.bz2', '.7z', '.rar', '.jar',
                      '.png', '.jpg', '.jpeg', '.gif', '.mp3', '.mp4', '.mov',
                      '.pdf', '.docx', '.xlsx', '.pptx'}

    if ext in naturally_high:
        if entropy > 7.0:
            return "expected", f"Entropy {entropy:.2f}/8.0 — expected for {ext} format (compressed/binary)"
        return "low", f"Entropy {entropy:.2f}/8.0 — within normal range for {ext}"

    if entropy < 4.0:
        return "low", f"Entropy {entropy:.2f}/8.0 — low, consistent with plain text"
    elif entropy < 6.0:
        return "moderate", f"Entropy {entropy:.2f}/8.0 — moderate compression or partially encoded"
    elif entropy < 7.0:
        return "elevated", f"Entropy {entropy:.2f}/8.0 — elevated, possible encoding or light obfuscation"
    elif entropy < 7.5:
        return "high", f"Entropy {entropy:.2f}/8.0 — high, likely encrypted or heavily obfuscated"
    else:
        return "very_high", f"Entropy {entropy:.2f}/8.0 — very high, strongly suggests encryption or packing"


def _block_entropy(data: bytes, block_size: int = 256) -> list[float]:
    """Compute entropy over blocks to detect partially-obfuscated sections."""
    entropies = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) >= 16:
            entropies.append(shannon_entropy(block))
    return entropies


def main() -> None:
    parser = argparse.ArgumentParser(description="File entropy analyzer")
    parser.add_argument("--file", required=True, help="Path to file to analyze")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"findings": []}

    try:
        if not os.path.isfile(args.file):
            result["error"] = f"File not found: {args.file}"
            print(json.dumps(result))
            return

        file_size = os.path.getsize(args.file)
        _, ext = os.path.splitext(args.file)

        with open(args.file, 'rb') as fh:
            content = fh.read()

        # Overall entropy
        overall_entropy = shannon_entropy(content)
        entropy_label, description = _classify_entropy(overall_entropy, ext)

        severity = "info"
        if entropy_label in ("high", "very_high") and ext not in {'.zip', '.gz', '.png', '.jpg'}:
            severity = "high"
        elif entropy_label == "elevated":
            severity = "medium"

        result["findings"].append({
            "severity": severity,
            "vulnerability_type": "entropy_analysis",
            "message": description,
            "file": args.file,
            "file_size_bytes": file_size,
            "entropy": round(overall_entropy, 4),
            "entropy_label": entropy_label,
        })

        # Block-level analysis for partially-obfuscated files
        if file_size > 512:
            block_entropies = _block_entropy(content)
            high_blocks = [e for e in block_entropies if e > 7.0]
            if high_blocks and entropy_label not in ("very_high", "high"):
                result["findings"].append({
                    "severity": "medium",
                    "vulnerability_type": "partial_encryption",
                    "message": (
                        f"{len(high_blocks)}/{len(block_entropies)} blocks have high entropy (>7.0) "
                        "— file may contain embedded encrypted/packed sections"
                    ),
                    "high_entropy_block_count": len(high_blocks),
                    "total_block_count": len(block_entropies),
                })

        # Check for PE file with high entropy sections (packed PE)
        is_pe = content[:2] == b'MZ'
        if is_pe and overall_entropy > 6.5:
            result["findings"].append({
                "severity": "high",
                "vulnerability_type": "packed_pe",
                "message": f"PE executable with entropy {overall_entropy:.2f} — likely packed (UPX, custom packer) to evade AV detection",
            })

    except Exception as exc:
        result["error"] = str(exc)
        result["findings"].append({
            "severity": "error",
            "vulnerability_type": "entropy_analysis",
            "message": f"Entropy analysis failed: {exc}",
        })
        logger.error("entropy_check error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
