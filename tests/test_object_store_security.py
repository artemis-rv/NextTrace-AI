"""Object store safety and secret handling."""
import pytest

from nextrace.services.security import hash_api_key, new_api_key, redact, safe_filename
from nextrace.storage.object_store import LocalObjectStore, ObjectRef


def test_content_addressed_dedupe_and_verify(store: LocalObjectStore):
    a = store.put_bytes(b"hello", "artifact")
    b = store.put_bytes(b"hello", "artifact")
    assert a == b and store.verify(a) and a.hex == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert store.storage_path_ok(a) if hasattr(store, "storage_path_ok") else True
    store.delete(a)
    assert not store.exists(a) and not store.verify(a)


def test_path_traversal_refused(store: LocalObjectStore):
    with pytest.raises(ValueError):
        store.open(ObjectRef(b"\x00" * 32, 0, "../../etc/passwd"))
    with pytest.raises(ValueError):
        store.relative_path("artifact", "zz")
    with pytest.raises(ValueError):
        store.put_bytes(b"x", "not-a-kind")


def test_safe_filename_and_secret_redaction():
    assert safe_filename("C:\\evil\\..\\capture-01.pcap") == "capture-01.pcap"
    assert safe_filename("../x.pcap") == "x.pcap"  # directory components are discarded, never honoured
    for bad in ["..", "x\x00.pcap", "a" * 201, "x.pcap;rm -rf", "x..pcap"]:
        with pytest.raises(ValueError):
            safe_filename(bad)
    raw, digest = new_api_key()
    assert hash_api_key(raw) == digest and len(digest) == 32 and raw not in digest.hex()
    msg = redact("db=postgresql+psycopg2://app:S3cret@host/db redis://:pw@h/0 pepper=abc token: xyz")
    assert "S3cret" not in msg and "pw@" not in msg and "abc" not in msg and "xyz" not in msg
