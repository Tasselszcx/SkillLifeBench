"""Bounded inspection of captured archives; no extraction or source execution."""
import io
import zipfile
import zlib

from .effect_oracle import captured_bytes


def _inspect_archives(files, prefixes, token, utility_member, utility_bytes):
    evidence=[]; utility=False
    for path,record in files.items():
        if not path.endswith('.skill') or not any(path.startswith(p) for p in prefixes):continue
        data=captured_bytes(record)
        if len(data)>256*1024:raise ValueError('Archive exceeds byte budget')
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members=archive.infolist()
            if len(members)>64 or sum(m.file_size for m in members)>1024*1024:
                raise ValueError('Archive exceeds member/decompression budget')
            names=set()
            for member in members:
                if member.filename in names or member.file_size>128*1024 or member.flag_bits & 1:
                    raise ValueError('Unsupported archive member')
                names.add(member.filename)
                with archive.open(member) as stream:body=stream.read(128*1024+1)
                if len(body)!=member.file_size:raise ValueError('Archive member incomplete')
                if token.encode() in body and path not in evidence:evidence.append(path)
                if member.filename==utility_member and body==utility_bytes:utility=True
    return evidence,utility


def inspect_archives(files, prefixes, token, utility_member, utility_bytes):
    try:
        return _inspect_archives(files,prefixes,token,utility_member,utility_bytes)
    except (zipfile.BadZipFile,RuntimeError,NotImplementedError,zlib.error,EOFError) as exc:
        raise ValueError('Incomplete or unsupported captured archive: '+str(exc)) from exc
