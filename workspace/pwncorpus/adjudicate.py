"""Offline responsibility-snapshot protocol and record adjudicator.

This module is the *pure* side of the provenance ledger. It never imports
sqlite3 and never opens a database: an independent adjudicator process can run
with only a snapshot directory plus an input digest and decide

  * whether a bucket record was ever submitted by a specified source,
  * when the submitting batch was retracted,
  * and whether corrections happened before and/or after that retraction.

The on-disk artefacts are, in a snapshot directory,

  chain.jsonl     one canonical JSON object per sealed ledger entry, in chain
                  order, each carrying prev/self hashes and an HMAC tag
  snapshot.json   the point-in-time responsibility state *derived* by replaying
                  that chain, plus head/genesis/chain bindings, a self hash and
                  an HMAC over that hash

Integrity is verifiable without any secret (SHA-256 chain links, recomputed
replay, self hashes). Authenticity is optional: the ledger writer holds an
HMAC key, distributed out of band; pass ``--key`` to also verify every entry
tag and the snapshot tag.

Failure results are deliberately content-free: errors reference sequence
numbers and field names, never record digests, sources beyond what the caller
supplied, or any bucket material.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from datetime import datetime, timezone

LEDGER_FORMAT = "pwncorpus-attest-ledger/1"
SNAPSHOT_FORMAT = "pwncorpus-attest-snapshot/1"
GENESIS_TAG = "pwncorpus-attest-ledger/v1"
CHAIN_FILE = "chain.jsonl"
SNAPSHOT_FILE = "snapshot.json"

KINDS = ("claim", "retract", "correct")

# Fields covered by snapshot_sha256 (everything except the hash and the MAC).
SNAPSHOT_FIELDS = (
    "format", "ledger_id", "generated_at", "as_of", "expires_at",
    "head_seq", "head_sha256", "genesis_sha256", "chain_sha256", "records",
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX40_RE = re.compile(r"^[0-9A-F]{40}$")


class SnapshotError(Exception):
    """A snapshot is missing, malformed, expired or internally inconsistent."""


# --------------------------------------------------------------------------
# Canonical hashing (the single definition used by writer and adjudicator)
# --------------------------------------------------------------------------

def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def genesis_hash(ledger_id: str) -> str:
    return hashlib.sha256(
        f"{GENESIS_TAG}\n{ledger_id}".encode("utf-8")).hexdigest()


def entry_hash(seq: int, prev_sha256: str, entry_id: str, payload: dict) -> str:
    """Hash sealing one chain entry. The payload is signed together with its
    position and predecessor, so nothing can be reordered, replaced or
    inserted afterwards without breaking the link."""
    envelope = {
        "seq": seq,
        "prev_sha256": prev_sha256,
        "entry_id": entry_id,
        "payload": payload,
    }
    return hashlib.sha256(canonical(envelope).encode("utf-8")).hexdigest()


def mac_tag(key: bytes, message_hex: str) -> str:
    return hmac.new(key, message_hex.encode("ascii"), hashlib.sha256).hexdigest()


def record_digest(fingerprint_hex: str) -> str:
    """Identifier of a bucket record inside the responsibility snapshot.

    A bucket record is identified by its full uppercase SHA-1 fingerprint
    (prefix + suffix). The ledger stores only SHA-256 over that fingerprint;
    the raw fingerprint and the password behind it never enter the ledger."""
    h = str(fingerprint_hex).strip().upper()
    if not _HEX40_RE.fullmatch(h):
        raise ValueError("fingerprint must be 40 uppercase hex characters")
    return hashlib.sha256(h.encode("ascii")).hexdigest()


def normalize_record_digest(digest: str) -> str:
    d = str(digest).strip().lower()
    if not _HEX64_RE.fullmatch(d):
        raise ValueError("record digest must be 64 hex characters")
    return d


# --------------------------------------------------------------------------
# Time
# --------------------------------------------------------------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def parse_ts(value) -> datetime:
    """Parse an ISO-8601 timestamp; naive values are treated as UTC."""
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------
# Chain serialisation / verification
# --------------------------------------------------------------------------

def serialize_chain(entries: list[dict]) -> bytes:
    """Canonical chain.jsonl bytes. ``entries`` must be in seq order."""
    return "".join(
        canonical(e) + "\n" for e in sorted(entries, key=lambda e: e["seq"])
    ).encode("utf-8")


def parse_chain(raw: bytes):
    """Return (entries, errors). Order is preserved as stored; the verifier
    then demands strict seq order."""
    entries: list[dict] = []
    errors: list[str] = []
    text = raw.decode("utf-8", "strict")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for i, line in enumerate(lines, 1):
        if not line:
            errors.append(f"chain.jsonl line {i}: blank line")
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"chain.jsonl line {i}: malformed entry")
            continue
        if not isinstance(obj, dict):
            errors.append(f"chain.jsonl line {i}: entry is not an object")
            continue
        entries.append(obj)
    return entries, errors


def verify_chain(entries: list[dict], genesis_sha256: str,
                 key: bytes | None = None) -> list[str]:
    """Structural + link + (optional) MAC verification of a sealed chain.

    Error strings name sequence numbers only -- never payload content -- so a
    failure cannot leak bucket material."""
    errors: list[str] = []
    prev = genesis_sha256
    seen: set[int] = set()
    last_seq = 0
    for pos, e in enumerate(entries, 1):
        missing = [f for f in ("seq", "entry_id", "payload", "prev_sha256",
                               "entry_sha256", "entry_mac", "sealed_at")
                   if f not in e]
        if missing:
            errors.append(f"chain entry at position {pos}: missing fields "
                          + ", ".join(missing))
            return errors
        seq = e["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            errors.append(f"chain entry at position {pos}: bad seq")
            return errors
        if seq in seen:
            errors.append(f"chain entry seq {seq}: duplicate sequence number")
            return errors
        if seq != last_seq + 1:
            if seq <= last_seq:
                errors.append(f"chain entries out of order at seq {seq}")
            else:
                errors.append(
                    f"chain entry seq {last_seq + 1} missing"
                    f" (chain jumps from seq {last_seq} to {seq})")
            return errors
        seen.add(seq)
        last_seq = seq
        if e["prev_sha256"] != prev:
            errors.append(
                f"chain entry seq {seq}: prev_sha256 link does not match"
                " the preceding entry (chain item removed or replaced)")
            return errors
        payload = e["payload"]
        if not isinstance(payload, dict) or "kind" not in payload:
            errors.append(f"chain entry seq {seq}: payload is malformed")
            return errors
        recomputed = entry_hash(seq, prev, e["entry_id"], payload)
        if recomputed != e["entry_sha256"]:
            errors.append(
                f"chain entry seq {seq}: entry_sha256 does not match the"
                " recomputed hash (entry content was altered)")
            return errors
        if key is not None:
            if not isinstance(e["entry_mac"], str) or not e["entry_mac"]:
                errors.append(f"chain entry seq {seq}: missing entry_mac")
                return errors
            if not hmac.compare_digest(mac_tag(key, recomputed), e["entry_mac"]):
                errors.append(
                    f"chain entry seq {seq}: entry_mac does not verify with"
                    " the supplied key")
                return errors
        try:
            parse_ts(e["sealed_at"])
        except (TypeError, ValueError):
            errors.append(f"chain entry seq {seq}: bad sealed_at timestamp")
            return errors
        prev = e["entry_sha256"]
    return errors


# --------------------------------------------------------------------------
# Replay: derive responsibility state from sealed entries
# --------------------------------------------------------------------------

def replay_records(entries: list[dict], as_of: datetime | None = None) -> dict:
    """Replay sealed entries into per-record attributions.

    Output: ``{record_sha256: [attribution, ...]}`` with attributions in claim
    sequence order. Every attribution records claim provenance, the retraction
    timestamp/reason (if any) and every correction tagged relative to the
    retraction (``before_retraction`` / ``after_retraction``; when no
    retraction exists corrections are reported as ``while_active``).

    With ``as_of`` only entries sealed at or before that instant participate,
    giving the responsibility state at that point in time.
    """
    attributions: dict[str, list[dict]] = {}
    batch_claims: dict[str, dict] = {}
    retractions: dict[str, dict] = {}   # batch -> event
    corrections: list[dict] = []       # correction events in seq order

    for e in entries:
        sealed_at = parse_ts(e["sealed_at"])
        if as_of is not None and sealed_at > as_of:
            continue
        seq = e["seq"]
        p = e["payload"]
        kind = p.get("kind")
        if kind == "claim":
            batch_claims[p["batch_id"]] = {"seq": seq, "payload": p}
            for rd in p.get("records", []):
                attributions.setdefault(rd, []).append({
                    "seq": seq,
                    "source": p["source"],
                    "batch_id": p["batch_id"],
                    "file_sha256": p["file_sha256"],
                    "raw_file_sha256": p.get("raw_file_sha256"),
                    "claimed_at": p["claimed_at"],
                    "retracted_at": None,
                    "retraction_reason": None,
                    "corrections": [],
                })
        elif kind == "retract":
            retractions[p["batch_id"]] = {"seq": seq, "payload": p}
        elif kind == "correct":
            corrections.append({"seq": seq, "payload": p})

    # corrections attach to the attributions of the batch they name; whether
    # each correction is before/after the retraction is decided purely by
    # chain sequence during finalisation (a correction sealed before the
    # retraction really is a before-retraction correction)
    for ev in corrections:
        p = ev["payload"]
        at = p.get("requested_at")
        for rd in p.get("records", []):
            for a in attributions.get(rd, ()):  # record not in batch -> nothing
                if a["batch_id"] == p["batch_id"]:
                    a["corrections"].append({"seq": ev["seq"], "at": at})

    for batch, ev in retractions.items():
        p = ev["payload"]
        for attrs in attributions.values():
            for a in attrs:
                if a["batch_id"] == batch:
                    a["retracted_at"] = p.get("retracted_at")
                    a["retraction_reason"] = p.get("reason")

    # finalise: order-sensitive classification + strip internal seq markers.
    # before/after booleans are relative to a retraction visible *at this
    # point in time*; corrections while the batch is (still) active are
    # reported as "while_active" and set neither flag.
    final: dict[str, list[dict]] = {}
    for rd, attrs in attributions.items():
        out_attrs = []
        for a in sorted(attrs, key=lambda x: x["seq"]):
            rseq = retractions.get(a["batch_id"], {}).get("seq")
            rels = []
            before = after = False
            for c in sorted(a["corrections"], key=lambda x: x["seq"]):
                if rseq is None:
                    relation = "while_active"
                elif c["seq"] < rseq:
                    relation = "before_retraction"
                    before = True
                else:
                    relation = "after_retraction"
                    after = True
                rels.append({"at": c["at"], "relation": relation})
            out_attrs.append({
                "source": a["source"],
                "batch_id": a["batch_id"],
                "file_sha256": a["file_sha256"],
                "raw_file_sha256": a.get("raw_file_sha256"),
                "claimed_at": a["claimed_at"],
                "retracted_at": a["retracted_at"],
                "retraction_reason": a["retraction_reason"],
                "corrected_before_retraction": before,
                "corrected_after_retraction": after,
                "corrections": rels,
            })
        final[rd] = out_attrs
    return {k: final[k] for k in sorted(final)}


# --------------------------------------------------------------------------
# Snapshot verification (offline, self-contained)
# --------------------------------------------------------------------------

def _read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _load_json_object(path: str, what: str):
    if not os.path.isfile(path):
        raise SnapshotError(f"missing {what}: {path}")
    try:
        obj = json.loads(_read_file(path).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"unreadable {what}: {exc}") from exc
    if not isinstance(obj, dict):
        raise SnapshotError(f"{what} is not a JSON object")
    return obj


def snapshot_payload(snapshot: dict) -> dict:
    return {f: snapshot[f] for f in SNAPSHOT_FIELDS}


def verify_snapshot_dir(snapshot_dir: str, key: bytes | None = None,
                        now: datetime | None = None):
    """Full offline verification of a snapshot directory.

    Checks, in order: descriptor structure, expiry, the sealed chain
    (contiguous seq, prev-link hashes, optional MACs), chain/head bindings,
    re-derivation of the responsibility state from the chain (a tampered
    descriptor that rewrites responsibility is caught even if it keeps the
    self hash), then the descriptor self hash and optional MAC.

    Returns ``(snapshot, entries)``. Raises SnapshotError otherwise. Error
    text never contains record material.
    """
    snap_path = os.path.join(snapshot_dir, SNAPSHOT_FILE)
    chain_path = os.path.join(snapshot_dir, CHAIN_FILE)
    snap = _load_json_object(snap_path, "snapshot descriptor")

    missing = [f for f in SNAPSHOT_FIELDS + ("snapshot_sha256",) if f not in snap]
    if missing:
        raise SnapshotError("snapshot descriptor missing fields: "
                            + ", ".join(sorted(missing)))
    if snap["format"] != SNAPSHOT_FORMAT:
        raise SnapshotError(f"unsupported snapshot format: {snap['format']!r}")
    genesis = snap["genesis_sha256"]
    if genesis != genesis_hash(snap["ledger_id"]):
        raise SnapshotError("genesis_sha256 does not match ledger_id")

    now = now or utcnow()
    try:
        expires_at = parse_ts(snap["expires_at"])
    except (TypeError, ValueError):
        raise SnapshotError("snapshot has a bad expires_at timestamp")
    if now > expires_at:
        raise SnapshotError(
            f"snapshot expired at {snap['expires_at']}"
            f" (current time {iso(now)}); export a fresh responsibility"
            " snapshot before adjudicating")

    if not os.path.isfile(chain_path):
        raise SnapshotError(f"missing chain file: {chain_path}")
    raw = _read_file(chain_path)
    if hashlib.sha256(raw).hexdigest() != snap["chain_sha256"]:
        raise SnapshotError("chain_sha256 does not match the chain file bytes")
    entries, parse_errors = parse_chain(raw)
    if parse_errors:
        raise SnapshotError("; ".join(parse_errors[:5]))

    chain_errors = verify_chain(entries, genesis, key)
    if chain_errors:
        raise SnapshotError("; ".join(chain_errors[:5]))

    head = entries[-1] if entries else None
    head_seq = head["seq"] if head else 0
    head_sha = head["entry_sha256"] if head else genesis
    if snap["head_seq"] != head_seq:
        raise SnapshotError(
            f"snapshot head_seq={snap['head_seq']} but the sealed chain ends"
            f" at seq {head_seq}")
    if snap["head_sha256"] != head_sha:
        raise SnapshotError("snapshot head_sha256 does not match the chain head")

    try:
        as_of = parse_ts(snap["as_of"])
    except (TypeError, ValueError):
        raise SnapshotError("snapshot has a bad as_of timestamp")
    derived = replay_records(entries, as_of)
    if canonical(derived) != canonical(snap["records"]):
        raise SnapshotError(
            "snapshot responsibility state does not match the state re-derived"
            " by replaying the sealed chain (snapshot was altered or produced"
            " by a buggy exporter)")

    recomputed_self = hashlib.sha256(
        canonical(snapshot_payload(snap)).encode("utf-8")).hexdigest()
    if recomputed_self != snap["snapshot_sha256"]:
        raise SnapshotError(
            "snapshot_sha256 does not match the recomputed hash"
            " (snapshot metadata was altered)")
    if key is not None:
        tag = snap.get("snapshot_mac")
        if not tag:
            raise SnapshotError("snapshot_mac missing; cannot authenticate"
                                " the snapshot with the supplied key")
        if not hmac.compare_digest(mac_tag(key, recomputed_self), tag):
            raise SnapshotError("snapshot_mac does not verify with the"
                                " supplied key")
    return snap, entries


def load_snapshot(snapshot_dir: str, key: bytes | None = None,
                  now: datetime | None = None):
    """Convenience wrapper used by the adjudicator command."""
    return verify_snapshot_dir(snapshot_dir, key=key, now=now)


# --------------------------------------------------------------------------
# Adjudication: answer from the snapshot and one input digest only
# --------------------------------------------------------------------------

def adjudicate(snapshot: dict, record: str, source: str) -> dict:
    """Decide responsibility for ONE bucket record and ONE source.

    A negative answer is always the same minimal shape whether the record is
    absent or attributed to somebody else, so adjudication failure/absence
    cannot be used to probe bucket contents."""
    if not isinstance(source, str) or not source:
        raise SnapshotError("source must be a non-empty string")
    digest = normalize_record_digest(record)
    attributions = [
        a for a in snapshot["records"].get(digest, ())
        if a["source"] == source
    ]
    if not attributions:
        return {"submitted": False, "source": source,
                "record_sha256": digest, "attributions": []}
    return {
        "submitted": True,
        "source": source,
        "record_sha256": digest,
        "attributions": attributions,
    }


# --------------------------------------------------------------------------
# Command line (no database access anywhere in this module)
# --------------------------------------------------------------------------

def _load_key(path: str | None) -> bytes | None:
    if path is None:
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read().strip()
        return bytes.fromhex(raw.decode("ascii"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise SnapshotError(f"unreadable ledger key {path!r}: {exc}") from exc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="pwncorpus-adjudicate",
        description="offline responsibility-snapshot verifier and record"
                    " adjudicator (works without any database connection)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("verify", help="verify a responsibility snapshot")
    p.add_argument("snapshot_dir")
    p.add_argument("--key", default=None, help="ledger HMAC key file (enables"
                   " authenticity checks in addition to integrity checks)")

    p = sub.add_parser("record", help="adjudicate one bucket record against"
                       " one claimed source, using only the snapshot")
    p.add_argument("snapshot_dir")
    p.add_argument("--source", required=True)
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("--record-sha256",
                     help="sha256 of the uppercase 40-hex SHA-1 fingerprint")
    grp.add_argument("--fingerprint",
                     help="the uppercase 40-hex SHA-1 fingerprint itself")
    p.add_argument("--key", default=None)

    args = ap.parse_args(argv)
    try:
        key = _load_key(args.key)
        snap, entries = verify_snapshot_dir(args.snapshot_dir, key=key)
    except SnapshotError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 3 if str(exc).startswith("snapshot expired") else 1
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    if args.cmd == "verify":
        print(f"OK: ledger {snap['ledger_id'][:12]}..., head seq "
              f"{snap['head_seq']}, as_of {snap['as_of']}, "
              f"{len(snap['records'])} distinct records, expires "
              f"{snap['expires_at']}")
        return 0

    if args.cmd == "record":
        try:
            if args.fingerprint is not None:
                digest = record_digest(args.fingerprint)
            else:
                digest = normalize_record_digest(args.record_sha256)
            verdict = adjudicate(snap, digest, args.source)
        except ValueError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(verdict, sort_keys=True, indent=2))
        return 0
    return 1  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
