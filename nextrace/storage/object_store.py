"""Content-addressed object store for large artifacts (PCAP, exports, model weights, SHAP arrays).

Objects are named by their SHA-256, written to a temp file and atomically renamed, then made
read-only. The relational database holds only the hash, size and relative path (objects table).
The interface is small on purpose so an S3/MinIO implementation can replace it without touching callers.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator, Protocol

CHUNK = 1024 * 1024
OBJECT_KINDS = {"pcap", "upload", "model", "shap", "artifact", "export", "report"}


@dataclass(frozen=True)
class ObjectRef:
    sha256: bytes
    size_bytes: int
    storage_path: str  # relative to the store root

    @property
    def hex(self) -> str:
        return self.sha256.hex()


class IntegrityError(RuntimeError):
    pass


class ObjectStore(Protocol):
    def put_stream(self, stream: BinaryIO, kind: str) -> ObjectRef: ...
    def put_bytes(self, data: bytes, kind: str) -> ObjectRef: ...
    def put_path(self, path: Path, kind: str) -> ObjectRef: ...
    def open(self, ref: ObjectRef) -> BinaryIO: ...
    def verify(self, ref: ObjectRef) -> bool: ...
    def delete(self, ref: ObjectRef) -> None: ...
    def exists(self, ref: ObjectRef) -> bool: ...


class LocalObjectStore:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "tmp").mkdir(exist_ok=True)

    # -- paths -------------------------------------------------------------------------------
    @staticmethod
    def relative_path(kind: str, sha_hex: str) -> str:
        if kind not in OBJECT_KINDS:
            raise ValueError(f"unknown object kind {kind!r}")
        if len(sha_hex) != 64 or any(c not in "0123456789abcdef" for c in sha_hex):
            raise ValueError("invalid sha256 hex")
        return f"{kind}/{sha_hex[:2]}/{sha_hex[2:4]}/{sha_hex}"

    def _abs(self, rel: str) -> Path:
        p = (self.root / rel).resolve()
        if self.root not in p.parents:
            raise ValueError("object path escapes the store root")
        return p

    # -- writes ------------------------------------------------------------------------------
    def put_stream(self, stream: BinaryIO, kind: str) -> ObjectRef:
        if kind not in OBJECT_KINDS:
            raise ValueError(f"unknown object kind {kind!r}")
        h = hashlib.sha256()
        size = 0
        fd, tmp_name = tempfile.mkstemp(dir=self.root / "tmp")
        try:
            with os.fdopen(fd, "wb") as out:
                while True:
                    chunk = stream.read(CHUNK)
                    if not chunk:
                        break
                    h.update(chunk)
                    size += len(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            rel = self.relative_path(kind, h.hexdigest())
            dest = self._abs(rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                os.unlink(tmp_name)  # identical content already stored
            else:
                os.replace(tmp_name, dest)
                os.chmod(dest, stat.S_IREAD | stat.S_IRGRP)
            return ObjectRef(h.digest(), size, rel)
        except Exception:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise

    def put_bytes(self, data: bytes, kind: str) -> ObjectRef:
        import io
        return self.put_stream(io.BytesIO(data), kind)

    def put_path(self, path: Path, kind: str) -> ObjectRef:
        path = Path(path)
        if path.is_symlink():
            raise ValueError("refusing to ingest a symlink")
        with open(path, "rb") as f:
            return self.put_stream(f, kind)

    # -- reads -------------------------------------------------------------------------------
    def exists(self, ref: ObjectRef) -> bool:
        return self._abs(ref.storage_path).is_file()

    def open(self, ref: ObjectRef) -> BinaryIO:
        return open(self._abs(ref.storage_path), "rb")

    def iter_chunks(self, ref: ObjectRef) -> Iterator[bytes]:
        with self.open(ref) as f:
            while chunk := f.read(CHUNK):
                yield chunk

    def verify(self, ref: ObjectRef) -> bool:
        p = self._abs(ref.storage_path)
        if not p.is_file():
            return False
        h = hashlib.sha256()
        size = 0
        with open(p, "rb") as f:
            while chunk := f.read(CHUNK):
                h.update(chunk)
                size += len(chunk)
        return h.digest() == ref.sha256 and size == ref.size_bytes

    def delete(self, ref: ObjectRef) -> None:
        p = self._abs(ref.storage_path)
        if p.exists():
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            p.unlink()

    def usage_bytes(self, kind: str | None = None) -> int:
        base = self.root / kind if kind else self.root
        total = 0
        for dirpath, _, files in os.walk(base):
            if Path(dirpath) == self.root / "tmp":
                continue
            for name in files:
                total += os.path.getsize(os.path.join(dirpath, name))
        return total

    def copy_out(self, ref: ObjectRef, dest: Path) -> None:
        """Export a verified copy (used for authorised evidence export)."""
        if not self.verify(ref):
            raise IntegrityError(f"object {ref.hex} failed integrity verification")
        shutil.copyfile(self._abs(ref.storage_path), dest)
