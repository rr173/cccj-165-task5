"""Append-only provenance responsibility ledger (SQLite).

Three process boundaries meet here:

  1. the command line submits claims / retractions / corrections;
  2. they land durably in this SQLite file as an append-only hash chain;
  3. an independent audit process exports a point-in-time *responsibility
     snapshot* (see :mod:`pwncorpus.adjudicate`) for a tool that has no
     database connection at all.

Writers go through a durable two-phase path:

    submit  -> ledger_pending (committed on its own, crash-proof)
            -> seal: pending rows are appended to ledger_entries one per
               write transaction, each chained to the previous entry and
               tagged with an HMAC key held outside the database

A process killed in the middle of sealing leaves the rest in
``ledger_pending``; the next writer (or ``ledger-seal``) drains from the last
chained item, so the chain never has a hole and never re-appends an entry.

The ledger stores ONLY digests: file SHA-256, and SHA-256 over each record's
40-hex SHA-1 fingerprint. No raw passwords, no raw fingerprints, no bucket
suffixes ever enter this database. Error messages name sources/batches the
caller supplied but never record material.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from datetime import timedelta

from . import adjudicate
from .delta import atomic_write

LEDGER_SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger_meta (
  key    TEXT PRIMARY KEY,
  value  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger_sources (
  source        TEXT PRIMARY KEY,
  token_sha256  TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

-- Durable staging area: rows here survive a killed process and are sealed in
-- id order by the next writer. Nothing in this table is part of the chain.
CREATE TABLE IF NOT EXISTS ledger_pending (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_id   TEXT NOT NULL UNIQUE,
  kind       TEXT NOT NULL CHECK (kind IN ('claim','retract','correct')),
  payload    TEXT NOT NULL,
  idem_key   TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_pending_order
  ON ledger_pending(id);

-- The append-only sealed chain. seq is gap-free; prev_sha256 links to the
-- previous entry or to the genesis hash. Rows are never updated or deleted.
CREATE TABLE IF NOT EXISTS ledger_entries (
  seq          INTEGER PRIMARY KEY,
  entry_id     TEXT NOT NULL UNIQUE,
  prev_sha256  TEXT NOT NULL,
  entry_sha256 TEXT NOT NULL,
  entry_mac    TEXT NOT NULL,
  payload      TEXT NOT NULL,
  sealed_at    TEXT NOT NULL
);

-- Sealed-claim lookup, maintained in the same transaction as the seal.
CREATE TABLE IF NOT EXISTS ledger_claim_index (
  batch_id     TEXT PRIMARY KEY,
  source       TEXT NOT NULL,
  file_sha256  TEXT NOT NULL,
  idem_key     TEXT NOT NULL UNIQUE,
  claim_seq    INTEGER NOT NULL UNIQUE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_claim_source_file
  ON ledger_claim_index(source, file_sha256);

CREATE TABLE IF NOT EXISTS ledger_retraction_index (
  batch_id     TEXT PRIMARY KEY,
  seq          INTEGER NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS ledger_correction_index (
  batch_id       TEXT NOT NULL,
  record_sha256  TEXT NOT NULL,
  seq            INTEGER NOT NULL,
  PRIMARY KEY (batch_id, record_sha256)
);
"""


class LedgerError(Exception):
    """Bad input or bad ledger state; messages never contain records."""


class LedgerNotFound(LedgerError):
    pass


class LedgerPermission(LedgerError):
    """The presented source token is missing/unknown or not allowed to act
    on the target batch."""


class LedgerConflict(LedgerError):
    """Parallel write contention or a newer state refusing to be overwritten."""


# --------------------------------------------------------------------------
# Initialisation / connection / key handling
# --------------------------------------------------------------------------

def default_key_path(ledger_path: str) -> str:
    return ledger_path + ".key"


def init_ledger(ledger_path: str, key_path: str | None = None) -> dict:
    """Create a brand-new ledger database and its HMAC key file.

    Refuses to clobber either artefact. The key file is created with 0600
    permissions next to the database unless an explicit path is given.
    """
    key_path = key_path or default_key_path(ledger_path)
    if os.path.exists(ledger_path):
        raise LedgerConflict(f"ledger already exists at {ledger_path!r}")
    if os.path.exists(key_path):
        raise LedgerConflict(f"ledger key file already exists at {key_path!r}")
    d = os.path.dirname(os.path.abspath(ledger_path))
    os.makedirs(d, exist_ok=True)

    key = secrets.token_bytes(32)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key.hex().encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)

    ledger_id = "led_" + secrets.token_hex(12)
    now = adjudicate.iso(adjudicate.utcnow())
    conn = sqlite3.connect(ledger_path, timeout=30, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT INTO ledger_meta(key, value) VALUES ('format', ?)",
            (adjudicate.LEDGER_FORMAT,))
        conn.execute(
            "INSERT INTO ledger_meta(key, value) VALUES ('ledger_id', ?)",
            (ledger_id,))
        conn.execute(
            "INSERT INTO ledger_meta(key, value) VALUES ('head_seq', '0')")
        conn.execute(
            "INSERT INTO ledger_meta(key, value) VALUES ('head_sha256', ?)",
            (adjudicate.genesis_hash(ledger_id),))
        conn.execute(
            "INSERT INTO ledger_meta(key, value) VALUES ('created_at', ?)",
            (now,))
    finally:
        conn.close()
    return {"ledger": ledger_path, "key": key_path, "ledger_id": ledger_id,
            "created_at": now}


def open_ledger(path: str) -> sqlite3.Connection:
    if not os.path.exists(path):
        raise LedgerNotFound(
            f"no ledger at {path!r}; run 'ledger-init' first")
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    _require_initialised(conn, path)
    return conn


def _require_initialised(conn, path: str) -> None:
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    if "ledger_entries" not in tables:
        raise LedgerError(
            f"{path!r} is not an initialised provenance ledger")


def load_key(key_path: str) -> bytes:
    try:
        with open(key_path, "rb") as fh:
            raw = fh.read().strip()
    except OSError as exc:
        raise LedgerError(f"cannot read ledger key {key_path!r}: {exc}") from exc
    try:
        return bytes.fromhex(raw.decode("ascii"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise LedgerError(f"ledger key {key_path!r} is not a hex key") from exc


# --------------------------------------------------------------------------
# Sources / tokens
# --------------------------------------------------------------------------

def register_source(conn, source: str) -> str:
    if not source or not isinstance(source, str):
        raise LedgerError("source is required")
    token = "lgs_" + secrets.token_urlsafe(32)
    now = adjudicate.iso(adjudicate.utcnow())
    try:
        with _write(conn):
            conn.execute(
                "INSERT INTO ledger_sources(source, token_sha256, created_at)"
                " VALUES (?,?,?)",
                (source, hashlib.sha256(token.encode()).hexdigest(), now))
    except sqlite3.IntegrityError:
        raise LedgerConflict(f"source {source!r} is already registered")
    return token  # shown once; only its hash persists


def _authenticate(conn, source: str, token: str):
    """Return the source row iff the token matches that exact source."""
    if not token:
        raise LedgerPermission("a source token is required")
    row = conn.execute(
        "SELECT source, token_sha256 FROM ledger_sources WHERE source = ?",
        (source,)).fetchone()
    presented = hashlib.sha256(token.encode()).hexdigest()
    if row is None or not secrets.compare_digest(
            row["token_sha256"], presented):
        raise LedgerPermission(
            "source permission error: unknown source or invalid token")
    return row


# --------------------------------------------------------------------------
# Write transactions with an explicit parallel-write failure
# --------------------------------------------------------------------------

class _WriteTx:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        for attempt in range(50):
            try:
                self.conn.execute("BEGIN IMMEDIATE")
                return self
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower() and attempt < 49:
                    import time
                    import random
                    time.sleep(0.01 + random.random() * 0.02)
                    continue
                raise LedgerConflict(
                    "parallel write conflict: the provenance ledger stayed"
                    " locked by another writer; retry the operation") from exc

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.conn.execute("COMMIT")
        else:
            self.conn.execute("ROLLBACK")
        return False


def _write(conn):
    return _WriteTx(conn)


# --------------------------------------------------------------------------
# Pending / seal internals
# --------------------------------------------------------------------------

def _meta(conn, key: str) -> str | None:
    r = conn.execute("SELECT value FROM ledger_meta WHERE key=?", (key,)).fetchone()
    return r["value"] if r else None


def _pending_payloads(conn, kind: str | None = None) -> list[dict]:
    if kind is None:
        rows = conn.execute(
            "SELECT payload FROM ledger_pending ORDER BY id").fetchall()
    else:
        rows = conn.execute(
            "SELECT payload FROM ledger_pending WHERE kind=? ORDER BY id",
            (kind,)).fetchall()
    return [json.loads(r["payload"]) for r in rows]


def _stage_pending(conn, kind: str, payload: dict, idem_key: str | None,
                   now_ts: str) -> str:
    """Insert a durable pending entry. Caller must already hold a write tx
    and have performed its duplicate checks."""
    entry_id = secrets.token_hex(16)
    conn.execute(
        "INSERT INTO ledger_pending(entry_id, kind, payload, idem_key,"
        " created_at) VALUES (?,?,?,?,?)",
        (entry_id, kind, adjudicate.canonical(payload), idem_key, now_ts))
    return entry_id


def _head(conn) -> tuple[int, str]:
    return int(_meta(conn, "head_seq")), _meta(conn, "head_sha256")


def _monotonic_seal_ts(conn) -> str:
    """Seal timestamps are strictly increasing along the chain. A fast writer
    sealing several entries within one millisecond gets a one-millisecond
    bump, so the recorded order is always total -- which is exactly what
    retraction/correction before/after ordering relies on.

    Comparison happens at the RECORDED precision (milliseconds): two wall
    times that differ only within a millisecond would format to the same
    string and must therefore be treated as a collision.
    """
    candidate = adjudicate.iso(adjudicate.utcnow())
    r = conn.execute(
        "SELECT sealed_at FROM ledger_entries ORDER BY seq DESC"
        " LIMIT 1").fetchone()
    if r is None:
        return candidate
    last = adjudicate.parse_ts(r["sealed_at"])
    if adjudicate.parse_ts(candidate) <= last:
        candidate = adjudicate.iso(last + timedelta(milliseconds=1))
    return candidate


def seal_pending(conn, key: bytes, progress=None) -> list[dict]:
    """Append every durable pending entry to the chain, one entry per write
    transaction, in staging id order. Safe and idempotent after a crash: it
    simply continues from the last chained item.

    Returns the list of sealed entries (chain objects).
    """
    sealed: list[dict] = []
    while True:
        with _write(conn):
            row = conn.execute(
                "SELECT id, entry_id, kind, payload FROM ledger_pending"
                " ORDER BY id LIMIT 1").fetchone()
            if row is None:
                break
            seq, prev_sha = _head(conn)
            payload = json.loads(row["payload"])
            seq += 1
            now_ts = _monotonic_seal_ts(conn)
            self_sha = adjudicate.entry_hash(
                seq, prev_sha, row["entry_id"], payload)
            tag = adjudicate.mac_tag(key, self_sha)
            conn.execute(
                "INSERT INTO ledger_entries(seq, entry_id, prev_sha256,"
                " entry_sha256, entry_mac, payload, sealed_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (seq, row["entry_id"], prev_sha, self_sha, tag,
                 adjudicate.canonical(payload), now_ts))
            conn.execute("DELETE FROM ledger_pending WHERE id=?", (row["id"],))
            conn.execute(
                "UPDATE ledger_meta SET value=? WHERE key='head_seq'",
                (str(seq),))
            conn.execute(
                "UPDATE ledger_meta SET value=? WHERE key='head_sha256'",
                (self_sha,))
            _update_seal_indexes(conn, payload, seq)
            # the progress hook runs BEFORE commit on purpose: an interrupted
            # process rolls the current entry back to ledger_pending while
            # earlier entries stay chained, so resuming continues exactly at
            # the last chained item
            if progress is not None:
                progress("entry-sealed", {
                    "seq": seq, "entry_id": row["entry_id"],
                    "prev_sha256": prev_sha, "entry_sha256": self_sha,
                    "entry_mac": tag, "payload": payload, "sealed_at": now_ts})
        sealed.append({
            "seq": seq, "entry_id": row["entry_id"],
            "prev_sha256": prev_sha, "entry_sha256": self_sha,
            "entry_mac": tag, "payload": payload, "sealed_at": now_ts})
    return sealed


def _update_seal_indexes(conn, payload: dict, seq: int) -> None:
    kind = payload["kind"]
    if kind == "claim":
        conn.execute(
            "INSERT INTO ledger_claim_index(batch_id, source, file_sha256,"
            " idem_key, claim_seq) VALUES (?,?,?,?,?)",
            (payload["batch_id"], payload["source"], payload["file_sha256"],
             payload["idem_key"], seq))
    elif kind == "retract":
        conn.execute(
            "INSERT INTO ledger_retraction_index(batch_id, seq) VALUES (?,?)",
            (payload["batch_id"], seq))
    elif kind == "correct":
        conn.executemany(
            "INSERT OR IGNORE INTO ledger_correction_index"
            "(batch_id, record_sha256, seq) VALUES (?,?,?)",
            [(payload["batch_id"], rd, seq) for rd in payload["records"]])


def _find_claim(conn, source: str, file_sha256: str, idem_key: str | None):
    """Look for an already-submitted identical claim in the sealed chain or
    in the durable pending area. An idempotency key reused by a DIFFERENT
    source is a conflict, never a silent alias to the other source's batch."""
    row = conn.execute(
        "SELECT * FROM ledger_claim_index WHERE source=? AND file_sha256=?",
        (source, file_sha256)).fetchone()
    if row is None and idem_key is not None:
        keyed = conn.execute(
            "SELECT * FROM ledger_claim_index WHERE idem_key=?",
            (idem_key,)).fetchone()
        if keyed is not None:
            if keyed["source"] != source:
                raise LedgerConflict(
                    "idempotency key is already bound to a claim of a"
                    " different source")
            row = keyed
    if row is not None:
        return ("sealed", row)
    for p in _pending_payloads(conn, "claim"):
        if p["source"] == source and (
                p["file_sha256"] == file_sha256
                or (idem_key is not None and p.get("idem_key") == idem_key)):
            return ("pending", p)
        if idem_key is not None and p.get("idem_key") == idem_key \
                and p["source"] != source:
            raise LedgerConflict(
                "idempotency key is already bound to a claim of a"
                " different source")
    return None


# --------------------------------------------------------------------------
# Submission API
# --------------------------------------------------------------------------

def _validate_records(records) -> list[str]:
    if not isinstance(records, list) or not records:
        raise LedgerError("records must be a non-empty list of record digests")
    return sorted({adjudicate.normalize_record_digest(r) for r in records})


def content_digest(records) -> str:
    """Canonical content digest of a claim's record set (order-independent),
    mirroring the ingestion pipeline's content_sha256 convention."""
    canon = "\n".join(_validate_records(records))
    return hashlib.sha256(canon.encode("ascii")).hexdigest()


def submit_claim(conn, key: bytes, source: str, token: str,
                 raw_file_sha256: str, records,
                 idem_key: str | None = None, progress=None) -> dict:
    """Append a source claim for one ingested file and its bucket records.

    The claim carries both the submitted file summary (SHA-256 of the exact
    file bytes, ``raw_file_sha256``) and the canonical content digest of the
    order-independent set of record digests; the latter drives idempotency, so
    re-submitting the same records in a different line order still returns the
    original batch. Idempotency is also available via an explicit key. The
    same claim is found whether already chained or still in the
    crash-recovery pending area.
    """
    raw_file_sha256 = adjudicate.normalize_record_digest(raw_file_sha256)
    records = _validate_records(records)
    file_sha256 = content_digest(records)
    now = adjudicate.utcnow()
    now_ts = adjudicate.iso(now)
    with _write(conn):
        _authenticate(conn, source, token)
        found = _find_claim(conn, source, file_sha256, idem_key)
        if found is None:
            batch_id = "bat_" + secrets.token_hex(12)
            idem_key = idem_key or f"content:{file_sha256}"
            payload = {
                "kind": "claim",
                "source": source,
                "batch_id": batch_id,
                "file_sha256": file_sha256,
                "raw_file_sha256": raw_file_sha256,
                "records": records,
                "idem_key": idem_key,
                "claimed_at": now_ts,
            }
            _stage_pending(conn, "claim", payload, idem_key, now_ts)
            staged = True
        else:
            staged = False
    seal_pending(conn, key, progress)
    return _claim_result(conn, source, file_sha256, idem_key,
                         duplicate=not staged)


def _claim_result(conn, source: str, file_sha256: str, idem_key: str | None,
                  duplicate: bool) -> dict:
    row = conn.execute(
        "SELECT batch_id, source, file_sha256, claim_seq FROM ledger_claim_index"
        " WHERE source=? AND (file_sha256=? OR idem_key=?)",
        (source, file_sha256, idem_key)).fetchone()
    if row is not None:
        e = conn.execute(
            "SELECT sealed_at FROM ledger_entries WHERE seq=?",
            (row["claim_seq"],)).fetchone()
        return {"duplicate": duplicate, "state": "sealed",
                "batch_id": row["batch_id"], "source": row["source"],
                "file_sha256": row["file_sha256"], "seq": row["claim_seq"],
                "sealed_at": e["sealed_at"]}
    # claimed but still pending (sealing was interrupted); report it as the
    # original record so a repeated submit still returns the same batch id
    for p in _pending_payloads(conn, "claim"):
        if p["source"] == source and (
                p["file_sha256"] == file_sha256
                or (idem_key is not None and p.get("idem_key") == idem_key)):
            return {"duplicate": True, "state": "pending",
                    "batch_id": p["batch_id"], "source": p["source"],
                    "file_sha256": p["file_sha256"], "seq": None,
                    "sealed_at": None}
    raise LedgerError("internal error: submitted claim disappeared")  # pragma: no cover


def _require_owned_batch(conn, source: str, token: str, batch_id: str):
    _authenticate(conn, source, token)
    claim = conn.execute(
        "SELECT source, claim_seq FROM ledger_claim_index WHERE batch_id=?",
        (batch_id,)).fetchone()
    if claim is None:
        pending = [p for p in _pending_payloads(conn, "claim")
                   if p["batch_id"] == batch_id]
        if pending:
            raise LedgerConflict(
                f"batch {batch_id!r} is staged but not yet chained; retry"
                " once sealing has caught up")
        raise LedgerNotFound(f"batch {batch_id!r} is not known to the ledger")
    if claim["source"] != source:
        raise LedgerPermission(
            f"source permission error: batch {batch_id!r} belongs to a"
            " different source")
    return claim


def retract_batch(conn, key: bytes, source: str, token: str, batch_id: str,
                  reason: str, idem_key: str | None = None,
                  progress=None) -> dict:
    """Record a retraction with its reason. Only the source that claimed the
    batch may retract it. A repeated retraction returns the original entry
    and appends nothing."""
    if not reason or not isinstance(reason, str) or not reason.strip():
        raise LedgerError("a non-empty retraction reason is required")
    now = adjudicate.utcnow()
    now_ts = adjudicate.iso(now)
    with _write(conn):
        claim = _require_owned_batch(conn, source, token, batch_id)
        existing = conn.execute(
            "SELECT seq FROM ledger_retraction_index WHERE batch_id=?",
            (batch_id,)).fetchone()
        pending_retract = next(
            (p for p in _pending_payloads(conn, "retract")
             if p["batch_id"] == batch_id), None)
        if existing is not None or pending_retract is not None:
            duplicate = True
        else:
            payload = {
                "kind": "retract",
                "source": source,
                "batch_id": batch_id,
                "reason": reason.strip(),
                "retracted_at": now_ts,
                "idem_key": idem_key,
            }
            _stage_pending(conn, "retract", payload, idem_key, now_ts)
            duplicate = False
    seal_pending(conn, key, progress)
    row = conn.execute(
        "SELECT seq FROM ledger_retraction_index WHERE batch_id=?",
        (batch_id,)).fetchone()
    if row is not None:
        e = conn.execute(
            "SELECT payload, sealed_at FROM ledger_entries WHERE seq=?",
            (row["seq"],)).fetchone()
        p = json.loads(e["payload"])
        return {"duplicate": duplicate, "state": "sealed",
                "batch_id": batch_id, "source": source,
                "retracted_at": p["retracted_at"], "reason": p["reason"],
                "sealed_at": e["sealed_at"], "seq": row["seq"]}
    return {"duplicate": True, "state": "pending", "batch_id": batch_id,
            "source": source, "retracted_at": None, "reason": None,
            "sealed_at": None, "seq": None}


def correct_records(conn, key: bytes, source: str, token: str, batch_id: str,
                    records, idem_key: str | None = None,
                    progress=None) -> dict:
    """Record false-positive corrections for records of an owned batch.

    Records not belonging to the batch are a digest mismatch error. Records
    already corrected (sealed or pending) are silently dropped; an entirely
    redundant request appends nothing and returns the original outcome.
    """
    requested = _validate_records(records)
    now = adjudicate.utcnow()
    now_ts = adjudicate.iso(now)
    with _write(conn):
        claim = _require_owned_batch(conn, source, token, batch_id)
        claim_payload = json.loads(conn.execute(
            "SELECT payload FROM ledger_entries WHERE seq=?",
            (claim["claim_seq"],)).fetchone()["payload"])
        members = set(claim_payload["records"])
        unknown = [r for r in requested if r not in members]
        if unknown:
            raise LedgerError(
                f"digest mismatch: {len(unknown)} submitted record digest(s)"
                " are not part of this batch")
        known = {r["record_sha256"] for r in conn.execute(
            "SELECT record_sha256 FROM ledger_correction_index"
            " WHERE batch_id=?", (batch_id,)).fetchall()}
        for p in _pending_payloads(conn, "correct"):
            if p["batch_id"] == batch_id:
                known.update(p["records"])
        fresh = sorted(set(requested) - known)
        if fresh:
            payload = {
                "kind": "correct",
                "source": source,
                "batch_id": batch_id,
                "records": fresh,
                "requested_at": now_ts,
                "idem_key": idem_key,
            }
            _stage_pending(conn, "correct", payload, idem_key, now_ts)
            duplicate = False
        else:
            duplicate = True
    seal_pending(conn, key, progress)
    rows = conn.execute(
        "SELECT seq FROM ledger_correction_index WHERE batch_id=?",
        (batch_id,)).fetchall()
    return {"duplicate": duplicate, "state": "sealed",
            "batch_id": batch_id, "source": source,
            "corrected_records": len(rows)}


# --------------------------------------------------------------------------
# Chain reading / verification
# --------------------------------------------------------------------------

def ledger_id(conn) -> str:
    return _meta(conn, "ledger_id")


def chain_entries(conn, up_to_seq: int | None = None) -> list[dict]:
    sql = ("SELECT seq, entry_id, prev_sha256, entry_sha256, entry_mac,"
           " payload, sealed_at FROM ledger_entries")
    params = ()
    if up_to_seq is not None:
        sql += " WHERE seq <= ?"
        params = (up_to_seq,)
    sql += " ORDER BY seq"
    out = []
    for r in conn.execute(sql, params):
        out.append({
            "seq": r["seq"], "entry_id": r["entry_id"],
            "prev_sha256": r["prev_sha256"], "entry_sha256": r["entry_sha256"],
            "entry_mac": r["entry_mac"], "payload": json.loads(r["payload"]),
            "sealed_at": r["sealed_at"],
        })
    return out


def verify_ledger(conn, key: bytes | None = None) -> list[str]:
    """Re-walk the whole chain from genesis and compare with the recorded
    head. Empty list means the ledger is internally consistent."""
    lid = ledger_id(conn)
    entries = chain_entries(conn)
    errors = adjudicate.verify_chain(entries, adjudicate.genesis_hash(lid), key)
    if errors:
        return errors
    head_seq, head_sha = _head(conn)
    last_seq = entries[-1]["seq"] if entries else 0
    last_sha = entries[-1]["entry_sha256"] if entries \
        else adjudicate.genesis_hash(lid)
    if head_seq != last_seq:
        errors.append(
            f"recorded head_seq={head_seq} but chain ends at seq {last_seq}")
    if head_sha != last_sha:
        errors.append("recorded head_sha256 does not match the chain head")
    return errors


def pending_count(conn) -> int:
    return conn.execute("SELECT COUNT(*) c FROM ledger_pending").fetchone()["c"]


# --------------------------------------------------------------------------
# Snapshot export (independent audit process; read-only)
# --------------------------------------------------------------------------

def snapshot_payload_for(entries: list[dict], ledger_id: str,
                         chain_sha256: str, generated_at: str,
                         as_of, expires_at: str) -> dict:
    head_seq = entries[-1]["seq"] if entries else 0
    head_sha = entries[-1]["entry_sha256"] if entries \
        else adjudicate.genesis_hash(ledger_id)
    records = adjudicate.replay_records(entries, as_of)
    return {
        "format": adjudicate.SNAPSHOT_FORMAT,
        "ledger_id": ledger_id,
        "generated_at": generated_at,
        "as_of": adjudicate.iso(as_of),
        "expires_at": expires_at,
        "head_seq": head_seq,
        "head_sha256": head_sha,
        "genesis_sha256": adjudicate.genesis_hash(ledger_id),
        "chain_sha256": chain_sha256,
        "records": records,
    }


def export_snapshot(conn, key: bytes, out_dir: str,
                    as_of: str | None = None, ttl_hours: float = 24.0,
                    force: bool = False, now=None) -> dict:
    """Export a self-contained, signed responsibility snapshot.

    Reads the chain in one stable snapshot. The on-disk snapshot is written
    atomically (chain file first, descriptor last). An existing snapshot is
    never overwritten by default; a *newer* snapshot (higher chain head) can
    never be downgraded to an older one, not even with ``force``.
    """
    if not isinstance(ttl_hours, (int, float)) or isinstance(ttl_hours, bool) \
            or ttl_hours <= 0:
        raise LedgerError("ttl-hours must be a positive number")
    wall_now = now or adjudicate.utcnow()

    conn.execute("BEGIN")  # stable read snapshot
    try:
        lid = ledger_id(conn)
        if verify_ledger(conn, key):
            raise LedgerError(
                "ledger chain fails verification; refusing to export a"
                " snapshot from a tampered or interrupted ledger")
        # The default point in time is "everything sealed so far": the latest
        # of the wall clock and the chain head's (possibly bumped, strictly
        # monotonic) seal time. An explicit as-of may not lie in the future.
        head_row = conn.execute(
            "SELECT sealed_at FROM ledger_entries ORDER BY seq DESC"
            " LIMIT 1").fetchone()
        head_time = adjudicate.parse_ts(head_row["sealed_at"]) \
            if head_row else wall_now
        if as_of is None:
            cutoff = max(wall_now, head_time)
        else:
            cutoff = adjudicate.parse_ts(as_of)
            if cutoff > wall_now or (head_row and cutoff > head_time):
                raise LedgerError("as-of timestamp lies in the future")
        # For a point-in-time snapshot the embedded chain is truncated to the
        # cutoff, so it cannot leak events (e.g. retraction reasons) sealed
        # after the reported point in time; head bindings point at the
        # truncated head, not the current ledger head.
        all_entries = chain_entries(conn)
        entries = [e for e in all_entries
                   if adjudicate.parse_ts(e["sealed_at"]) <= cutoff]
    finally:
        conn.execute("ROLLBACK")

    chain_bytes = adjudicate.serialize_chain(entries)
    chain_sha256 = hashlib.sha256(chain_bytes).hexdigest()
    expires = wall_now + timedelta(hours=float(ttl_hours))
    payload = snapshot_payload_for(
        entries, lid, chain_sha256, adjudicate.iso(wall_now),
        cutoff, adjudicate.iso(expires))
    self_sha = hashlib.sha256(
        adjudicate.canonical(adjudicate.snapshot_payload(payload)).encode()
    ).hexdigest()
    payload["snapshot_sha256"] = self_sha
    payload["snapshot_mac"] = adjudicate.mac_tag(key, self_sha)

    existing = os.path.join(out_dir, adjudicate.SNAPSHOT_FILE)
    if os.path.exists(existing):
        try:
            with open(existing, "r", encoding="utf-8") as fh:
                old = json.load(fh)
            old_head = int(old.get("head_seq", -1))
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise LedgerConflict(
                f"refusing to replace unreadable snapshot in {out_dir!r};"
                f" move it aside first ({exc})") from exc
        if old_head > payload["head_seq"]:
            raise LedgerConflict(
                f"refusing to overwrite: existing snapshot carries newer"
                f" responsibility state (head seq {old_head}) than this"
                f" export (head seq {payload['head_seq']})")
        if old_head == payload["head_seq"] and not force:
            return {"unchanged": True, "out": out_dir,
                    "head_seq": payload["head_seq"],
                    "ledger_id": payload["ledger_id"]}
        # old_head < payload["head_seq"]: newer responsibility state is
        # allowed to refresh an older snapshot automatically

    os.makedirs(out_dir, exist_ok=True)
    atomic_write(os.path.join(out_dir, adjudicate.CHAIN_FILE), chain_bytes)
    atomic_write(
        os.path.join(out_dir, adjudicate.SNAPSHOT_FILE),
        (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return {"unchanged": False, "out": out_dir,
            "head_seq": payload["head_seq"], "ledger_id": lid,
            "as_of": payload["as_of"], "expires_at": payload["expires_at"],
            "records": len(payload["records"]),
            "snapshot_sha256": self_sha}


def status(conn) -> dict:
    lid = ledger_id(conn)
    head_seq, head_sha = _head(conn)
    return {
        "ledger_id": lid,
        "head_seq": int(head_seq),
        "head_sha256": head_sha,
        "pending": pending_count(conn),
        "sources": conn.execute(
            "SELECT COUNT(*) c FROM ledger_sources").fetchone()["c"],
        "claims": conn.execute(
            "SELECT COUNT(*) c FROM ledger_claim_index").fetchone()["c"],
        "retractions": conn.execute(
            "SELECT COUNT(*) c FROM ledger_retraction_index").fetchone()["c"],
        "chain_ok": not verify_ledger(conn),
    }
