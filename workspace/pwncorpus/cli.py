"""Admin CLI for pwncorpus.

  python -m pwncorpus.cli init --db corpus.db
  python -m pwncorpus.cli token --db corpus.db --label ingestor --scopes ingest
  python -m pwncorpus.cli ingest --db corpus.db --source breach-2026Q3 --file leaks.txt
  python -m pwncorpus.cli build --db corpus.db --k 50
  python -m pwncorpus.cli refresh --db corpus.db --version 3
  python -m pwncorpus.cli activate --db corpus.db --version 3
  python -m pwncorpus.cli retract --db corpus.db --batch <id>
  python -m pwncorpus.cli export --db corpus.db --version 3 --out export-v3/
  python -m pwncorpus.cli delta-generate --db corpus.db \
      --from-version 2 --to-version 3 --out delta-v2-v3/

# provenance responsibility ledger (append-only, separate database)
  python -m pwncorpus.cli ledger-init --ledger ledger.db
  python -m pwncorpus.cli ledger-source --ledger ledger.db --source breach-2026Q3
  python -m pwncorpus.cli attest-submit --ledger ledger.db --source breach-2026Q3 \
      --token lgs_... --file leak.txt
  python -m pwncorpus.cli attest-retract --ledger ledger.db --source breach-2026Q3 \
      --token lgs_... --batch bat_... --reason "court order 2026-09-30"
  python -m pwncorpus.cli attest-correct --ledger ledger.db --source breach-2026Q3 \
      --token lgs_... --batch bat_... --file falsepositives.txt
  python -m pwncorpus.cli ledger-seal --ledger ledger.db
  python -m pwncorpus.cli ledger-snapshot --ledger ledger.db --out snapshot/
  python -m pwncorpus.cli ledger-status --ledger ledger.db
  python -m pwncorpus.adjudicate verify snapshot/
  python -m pwncorpus.adjudicate record snapshot/ --source breach-2026Q3 \
      --record-sha256 <hex64>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

from . import adjudicate, core, db, delta, ledger, verifier


def _conn(args):
    return db.connect(args.db)


def _read_record_file(path: str) -> list[str]:
    """Parse a record list file into record digests (sha256 of the 40-hex
    fingerprint). Lines are either

      * a 40-hex SHA-1 fingerprint (prefix+suffix; only its sha256 is kept),
      * ``sha256rec:<64 hex>`` for a pre-hashed record digest.

    Raw passwords are deliberately NOT accepted here: the responsibility
    ledger only knows digests."""
    records = []
    with open(path, "r", encoding="utf-8", errors="strict") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith("sha256rec:"):
                try:
                    records.append(adjudicate.normalize_record_digest(line[12:]))
                except ValueError:
                    raise ledger.LedgerError(
                        f"{path}:{lineno}: malformed sha256 record digest")
            else:
                try:
                    records.append(adjudicate.record_digest(line))
                except ValueError:
                    raise ledger.LedgerError(
                        f"{path}:{lineno}: expected a 40-hex SHA-1 fingerprint"
                        " or 'sha256rec:<hex64>'")
    return records


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_ledger(args) -> int:
    conn = ledger.open_ledger(args.ledger)
    key = None
    if args.cmd != "ledger-status":
        key = ledger.load_key(args.ledger_key
                              or ledger.default_key_path(args.ledger))
    try:
        if args.cmd == "ledger-source":
            token = ledger.register_source(conn, args.source)
            print(f"source {args.source!r} registered")
            print(f"submit token (store it now, it is not recoverable): {token}")
            return 0

        if args.cmd == "attest-submit":
            file_sha = _file_sha256(args.file)
            if args.expected_sha256 is not None \
                    and file_sha.lower() != args.expected_sha256.lower():
                print(f"FAIL: file digest mismatch: the file's SHA-256 does"
                      f" not match --expected-sha256", file=sys.stderr)
                return 1
            records = _read_record_file(args.file)
            result = ledger.submit_claim(
                conn, key, args.source, args.token, file_sha, records,
                args.idempotency_key)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

        if args.cmd == "attest-retract":
            result = ledger.retract_batch(
                conn, key, args.source, args.token, args.batch, args.reason,
                args.idempotency_key)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

        if args.cmd == "attest-correct":
            records = _read_record_file(args.file)
            result = ledger.correct_records(
                conn, key, args.source, args.token, args.batch, records,
                args.idempotency_key)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

        if args.cmd == "ledger-seal":
            sealed = ledger.seal_pending(conn, key)
            print(json.dumps({"sealed": len(sealed)}, indent=2))
            return 0

        if args.cmd == "ledger-status":
            print(json.dumps(ledger.status(conn), indent=2, sort_keys=True))
            return 0

        if args.cmd == "ledger-snapshot":
            result = ledger.export_snapshot(
                conn, key, args.out, as_of=args.as_of,
                ttl_hours=args.ttl_hours, force=args.force)
            if result.get("unchanged"):
                print(f"OK: snapshot in {result['out']} already at head seq"
                      f" {result['head_seq']}; nothing written")
            else:
                print(f"OK: snapshot exported to {result['out']} (head seq"
                      f" {result['head_seq']}, {result['records']} distinct"
                      f" records, as_of {result['as_of']}, expires"
                      f" {result['expires_at']})")
                print(f"    snapshot {result['snapshot_sha256'][:16]}...")
            return 0
    except ledger.LedgerError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 1  # pragma: no cover


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pwncorpus")
    ap.add_argument("--db", default="corpus.db", help="SQLite database path")
    ap.add_argument("--ledger", default="ledger.db",
                    help="provenance ledger SQLite path (separate from --db)")
    ap.add_argument("--ledger-key", default=None,
                    help="ledger HMAC key file (defaults to <ledger>.key)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the database schema")

    p = sub.add_parser("token", help="create an API token (shown once)")
    p.add_argument("--label", required=True)
    p.add_argument("--scopes", required=True,
                   help="comma separated: ingest,retract,publish")

    p = sub.add_parser("ingest", help="ingest a batch file (one password or "
                       "'sha1:<hex>' per line)")
    p.add_argument("--source", required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--idempotency-key", default=None)

    p = sub.add_parser("build", help="build a candidate publication")
    p.add_argument("--k", type=int, default=core.DEFAULT_THRESHOLD_K,
                   help="minimum bucket set size")

    p = sub.add_parser("activate", help="atomically activate a candidate "
                       "(fails with a conflict if the candidate is stale)")
    p.add_argument("--version", type=int, required=True)

    p = sub.add_parser("refresh", help="rebuild a stale candidate from current "
                       "source data, keeping its version and threshold k")
    p.add_argument("--version", type=int, required=True)

    p = sub.add_parser("retract", help="retract a batch (effective next build)")
    p.add_argument("--batch", required=True)

    p = sub.add_parser("correct", help="exclude fingerprints of a batch "
                       "(false positives), effective next build")
    p.add_argument("--batch", required=True)
    p.add_argument("--file", required=True,
                   help="file with one password or 'sha1:<hex>' per line")

    p = sub.add_parser("export", help="export a version for offline verification")
    p.add_argument("--version", type=int, required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("delta-generate",
                       help="build a verifiable incremental package between two"
                       " stored releases (offline hosts can also use"
                       " 'python -m pwncorpus.delta build' on two exports)")
    p.add_argument("--from-version", type=int, required=True,
                   help="baseline release already present in the mirror")
    p.add_argument("--to-version", type=int, required=True,
                   help="target release")
    p.add_argument("--out", required=True, help="output delta package directory")

    p = sub.add_parser("status", help="show publications and batch stats")

    p = sub.add_parser("serve", help="run the HTTP server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)

    # ---- provenance responsibility ledger --------------------------------
    sub.add_parser("ledger-init", help="create the append-only provenance"
                   " ledger database and its HMAC key")

    p = sub.add_parser("ledger-source",
                       help="register a source and print its submit token"
                       " (shown once)")
    p.add_argument("--source", required=True)

    p = sub.add_parser("attest-submit", help="append a source claim for an"
                       " ingested file (one 40-hex SHA-1 fingerprint per"
                       " line, may be 'sha256rec:<hex64>' record digests)")
    p.add_argument("--source", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--file", required=True,
                   help="ingested source file; its SHA-256 is the claim digest")
    p.add_argument("--idempotency-key", default=None)
    p.add_argument("--expected-sha256", default=None,
                   help="require the file SHA-256 to equal this value")

    p = sub.add_parser("attest-retract",
                       help="record a retraction with reason (owner source"
                       " only); effective ordering is given by the chain")
    p.add_argument("--source", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--batch", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--idempotency-key", default=None)

    p = sub.add_parser("attest-correct", help="record false-positive"
                       " corrections for records of an owned batch")
    p.add_argument("--source", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--batch", required=True)
    p.add_argument("--file", required=True,
                   help="one 40-hex SHA-1 fingerprint per line, or"
                   " 'sha256rec:<hex64>' record digests")
    p.add_argument("--idempotency-key", default=None)

    sub.add_parser("ledger-seal", help="drain staged entries into the chain"
                   " (recovery entry point after an interrupted writer)")

    p = sub.add_parser("ledger-status", help="show ledger head, pending"
                       " entries and chain consistency")

    p = sub.add_parser("ledger-snapshot",
                       help="audit export of a point-in-time responsibility"
                       " snapshot for the offline adjudicator")
    p.add_argument("--out", required=True)
    p.add_argument("--as-of", default=None,
                   help="ISO-8601 cutoff (default: current time)")
    p.add_argument("--ttl-hours", type=float, default=24.0,
                   help="snapshot validity window (default 24h)")
    p.add_argument("--force", action="store_true",
                   help="replace an existing snapshot (never downgrades a"
                   " newer one)")

    args = ap.parse_args(argv)

    if args.cmd == "init":
        db.init(args.db)
        print(f"initialised {args.db}")
        return 0

    if args.cmd == "ledger-init":
        info = ledger.init_ledger(args.ledger, args.ledger_key)
        print(f"initialised provenance ledger {info['ledger']}")
        print(f"ledger_id {info['ledger_id']}")
        print(f"HMAC key written to {info['key']} (0600; distribute out of"
              " band to auditors)")
        return 0

    if args.cmd == "serve":
        from .server import make_server
        srv = make_server(args.db, args.host, args.port)
        print(f"serving on http://{args.host}:{args.port}  (db={args.db})")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0

    if args.cmd in ("ledger-source", "attest-submit", "attest-retract",
                    "attest-correct", "ledger-seal", "ledger-status",
                    "ledger-snapshot"):
        return _run_ledger(args)

    conn = _conn(args)
    try:
        if args.cmd == "token":
            token = core.create_token(conn, args.label, args.scopes.split(","))
            print(f"token (store it now, it is not recoverable): {token}")
            return 0

        if args.cmd == "ingest":
            items = []
            with open(args.file, "r", encoding="utf-8", errors="surrogateescape") as fh:
                for line in fh:
                    line = line.rstrip("\r\n")
                    if not line:
                        continue
                    if line.lower().startswith("sha1:"):
                        items.append({"sha1": line[5:]})
                    else:
                        items.append(line)
            result = core.ingest_batch(conn, args.source, items,
                                       args.idempotency_key)
            items.clear()
            print(json.dumps(result, indent=2))
            return 0

        if args.cmd == "build":
            print(json.dumps(core.build_candidate(conn, args.k), indent=2))
            return 0

        if args.cmd == "activate":
            print(json.dumps(core.activate(conn, args.version), indent=2))
            return 0

        if args.cmd == "refresh":
            print(json.dumps(core.refresh_candidate(conn, args.version), indent=2))
            return 0

        if args.cmd == "retract":
            print(json.dumps(core.retract_batch(conn, args.batch), indent=2))
            return 0

        if args.cmd == "correct":
            items = []
            with open(args.file, "r", encoding="utf-8", errors="surrogateescape") as fh:
                for line in fh:
                    line = line.rstrip("\r\n")
                    if not line:
                        continue
                    if line.lower().startswith("sha1:"):
                        items.append({"sha1": line[5:]})
                    else:
                        items.append(line)
            print(json.dumps(core.add_corrections(conn, args.batch, items), indent=2))
            return 0

        if args.cmd == "export":
            manifest = core.export_version(conn, args.version, args.out)
            print(f"exported v{args.version} to {args.out} "
                  f"({len(manifest['files'])} buckets, "
                  f"manifest {manifest['manifest_sha256'][:16]}...)")
            return 0

        if args.cmd == "delta-generate":
            import tempfile
            with tempfile.TemporaryDirectory(prefix="pwncorpus-delta-") as tmp:
                fdir = os.path.join(tmp, "from")
                tdir = os.path.join(tmp, "to")
                core.export_version(conn, args.from_version, fdir)
                core.export_version(conn, args.to_version, tdir)
                if verifier.verify_export(fdir) or verifier.verify_export(tdir):
                    raise core.CorpusError(
                        "internal export failed verification; aborting delta build")
                meta = delta.build_delta(fdir, tdir, args.out)
            s = delta.delta_summary(meta)
            print(f"built delta v{s['from_version']} -> v{s['to_version']} "
                  f"in {args.out} "
                  f"(added {s['buckets_added']}, modified {s['buckets_modified']},"
                  f" deleted {s['buckets_deleted']}, unchanged "
                  f"{s['buckets_unchanged']} buckets)")
            return 0

        if args.cmd == "status":
            state = core.review_state(conn)
            print(json.dumps({
                "active_version": core.current_version(conn),
                "corpus_state": state["corpus_state"],
                "publications": state["publications"],
                "stats": state["stats"],
            }, indent=2))
            return 0
    except core.CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except delta.DeltaError as exc:  # delta-generate validation failures
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 1  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
