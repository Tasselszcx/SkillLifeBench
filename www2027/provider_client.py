"""Immutable local receipt writer used by the released evaluator.

Transport configuration belongs to skilllifebench.client and environment
variables; this module never loads a private provider file or dotenv file.
"""
import json
from pathlib import Path


def save_receipt(path, receipt):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
