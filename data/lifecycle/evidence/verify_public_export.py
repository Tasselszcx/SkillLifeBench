#!/usr/bin/env python3
"""Verify public archive bytes and privacy proofs without private data or imports."""
import argparse
import base64
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import tarfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            value.update(block)
    return value.hexdigest()


class Parts(io.RawIOBase):
    def __init__(self, paths):
        self.paths, self.current = iter(paths), None

    def readable(self):
        return True

    def read(self, size=-1):
        size = 1048576 if size < 0 else size
        result = bytearray()
        while len(result) < size:
            if self.current is None:
                try:
                    self.current = next(self.paths).open("rb")
                except StopIteration:
                    break
            block = self.current.read(size - len(result))
            if block:
                result.extend(block)
            else:
                self.current.close()
                self.current = None
        return bytes(result)

    def close(self):
        if self.current is not None:
            self.current.close()
        super().close()


def derivative(row, raw):
    proof = row["transformation"]
    require(proof.get("all_other_bytes_exact") is True, "Missing unchanged-byte proof")
    intervals = []
    for interval in proof["unchanged_byte_intervals"]:
        p0, p1 = interval["public_start"], interval["public_end"]
        o0, o1 = interval["original_start"], interval["original_end"]
        require(p1 - p0 == o1 - o0 and p1 >= p0 and o1 >= o0, "Invalid unchanged interval")
        require(hashlib.sha256(raw[p0:p1]).hexdigest() == interval["sha256"], "Interval hash differs")
        intervals.append((p0, p1, o0, o1))
    if proof.get("schema") == "skilllifebench-privacy-derivative/v1":
        changes = proof["replacements"]
        for change in changes:
            p0, p1 = change["public_start"], change["public_end"]
            o0, o1 = change["original_start"], change["original_end"]
            token = raw[p0:p1]
            require(hashlib.sha256(token).hexdigest() == change["public_token_sha256"], "Replacement hash differs")
            kind = change["kind"]
            require(kind in {"credential-header", "opaque-provider-state", "host-path-alias", "encoded-json-publication"}, "Unknown publication transform")
            if kind in {"credential-header", "opaque-provider-state"}:
                require(token == b"null", "Opaque state is not null")
            elif kind == "host-path-alias":
                require(b"/slb/" in token, "Missing host-path alias")
            else:
                value = json.loads(token)
                body = base64.b64decode(value, validate=True) if change["encoding"] == "base64" else value.encode()
                require(hashlib.sha256(body).hexdigest() == change["public_decoded_sha256"], "Decoded-body hash differs")
                json.loads(body)
            intervals.append((p0, p1, o0, o1))
    else:
        changes = proof["redactions"]
        for change in changes:
            public, original = change["public_json_token"], change["original_json_token"]
            p0, p1 = public["start_byte"], public["end_byte"]
            require(raw[p0:p1] == b"null", "Credential header is not null")
            intervals.append((p0, p1, original["start_byte"], original["end_byte"]))
    require(bool(changes), "Missing publication replacements")
    public_end = original_end = 0
    for p0, p1, o0, o1 in sorted(intervals):
        require(p0 == public_end and o0 == original_end and 0 <= p0 <= p1 <= len(raw)
                and 0 <= o0 <= o1 <= row["original_bytes"], "Publication proof gap or overlap")
        public_end, original_end = p1, o1
    require(public_end == len(raw) and original_end == row["original_bytes"], "Incomplete publication proof")


def verify(index_path):
    index_path = Path(index_path).resolve()
    metadata = json.loads(index_path.read_text())
    parts, combined = [], hashlib.sha256()
    for part in metadata["parts"]:
        name = PurePosixPath(part["name"])
        require(len(name.parts) == 1 and name.name != "..", "Unsafe archive part name")
        path = index_path.parent / name.name
        require(0 < part["bytes"] <= 20 * 1024 * 1024 and path.stat().st_size == part["bytes"]
                and digest(path) == part["sha256"], "Archive part integrity differs")
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1048576), b""):
                combined.update(block)
        parts.append(path)
    require(combined.hexdigest() == metadata["concatenated_sha256"], "Combined archive hash differs")
    observed, rows, by_name = {}, [], {}
    with Parts(parts) as pieces, lzma.LZMAFile(pieces, "rb") as stream:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                name = PurePosixPath(member.name)
                require(member.isfile() and not name.is_absolute() and ".." not in name.parts
                        and member.name not in observed, "Unsafe or duplicate archive member")
                raw = archive.extractfile(member).read()
                observed[member.name] = (len(raw), hashlib.sha256(raw).hexdigest())
                if member.name == metadata["portable_index_member"]:
                    rows = [json.loads(line) for line in raw.splitlines()]
                    by_name = {row["public_path"]: row for row in rows}
                    require(len(by_name) == len(rows), "Duplicate public path")
                else:
                    require(bool(rows), "Portable index must be the first archive member")
                    row = by_name.get(member.name)
                    if row is not None and not row["byte_identical"]:
                        derivative(row, raw)
    aliases = {}
    for row in rows:
        require(observed[row["public_path"]] == (row["public_bytes"], row["public_sha256"]), "Public evidence hash differs")
        if row["byte_identical"]:
            require(row["original_sha256"] == row["public_sha256"] and row["original_bytes"] == row["public_bytes"], "False byte-identity claim")
        for alias in row["original_paths"]:
            binding = (alias, row["original_sha256"])
            require(binding not in aliases or aliases[binding] == row["public_sha256"], "Conflicting original binding")
            aliases[binding] = row["public_sha256"]
    require(len(rows) == metadata["evidence_files"], "Evidence count differs")
    for member_key, hash_key in (("portable_index_member", "portable_index_sha256"), ("proof_scope_member", "proof_scope_sha256"), ("privacy_publication_member", "privacy_publication_sha256")):
        require(observed[metadata[member_key]][1] == metadata[hash_key], "Release metadata hash differs")
    privacy = sum(row.get("transformation", {}).get("schema") == "skilllifebench-privacy-derivative/v1" for row in rows)
    return {"verified": True, "evidence_files": len(rows), "privacy_derivative_files": privacy,
            "header_derivative_files": sum(not row["byte_identical"] for row in rows) - privacy,
            "automatic_raw_hash_replay_compatibility": False, "original_and_public_hashes_distinguished": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-index", required=True)
    arguments = parser.parse_args()
    print(json.dumps(verify(arguments.archive_index), indent=2))
