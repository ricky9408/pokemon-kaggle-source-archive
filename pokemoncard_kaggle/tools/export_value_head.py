#!/usr/bin/env python3
"""Export the historical post-shift neural value head to a pure-Python binary."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import struct

import numpy as np


MAGIC = b"PVH1"


def export(source: Path, output: Path) -> dict[str, object]:
    data = np.load(source)
    buckets = int(data["buckets"][0])
    dimension = int(data["dim"][0])
    hidden = int(data["V1"].shape[0])
    expected = {
        "emb": (buckets, dimension),
        "V1": (hidden, dimension),
        "vb1": (hidden,),
        "V2": (hidden,),
        "vb2": (1,),
    }
    for name, shape in expected.items():
        if tuple(data[name].shape) != shape:
            raise ValueError(f"unexpected {name} shape: {data[name].shape}")
    payload = bytearray(struct.pack("<4sIII", MAGIC, buckets, dimension, hidden))
    for name in ("emb", "V1", "vb1", "V2", "vb2"):
        payload.extend(np.asarray(data[name], dtype="<f4").tobytes(order="C"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    manifest = {
        "schema": "public_value_head_binary_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(source),
        "source_sha256": sha256(source.read_bytes()).hexdigest(),
        "output": str(output),
        "output_sha256": sha256(payload).hexdigest(),
        "buckets": buckets,
        "dimension": dimension,
        "hidden": hidden,
        "training_note": "strategy/policy_value_net_fresh_20260703.md",
        "trust": "external_postshift_value_prior_auc_0.600_not_promotion_evidence",
    }
    output.with_suffix(output.suffix + ".json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(export(args.source, args.output), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
