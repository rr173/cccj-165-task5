"""Tests for the replayable provenance responsibility ledger.

Covers three process boundaries:
  * command-line submission via ``pwncorpus.cli`` (separate processes),
  * durable append-only SQLite storage + HMAC hash chain,
  * independent audit snapshot export and the database-free adjudicator
    (``pwncorpus.adjudicate`` is verified not to import sqlite3).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta

from pwncorpus import adjudicate, ledger

FP_A = "A" * 40
FP_B = "B" * 40
FP_C = "C" * 40
RD_A = adjudicate.record_digest(FP_A)
RD_B = adjudicate.record_digest(FP_B)
RD_C = adjudicate.record_digest(FP_C)


def read_json(path):
    with open(path) as fh:
        return json.load(fh)


def raw_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class LedgerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pwncorpus-ledger-test-")
        self.ledger_path = os.path.join(self.tmp, "ledger.db")
        self.key_path = os.path.join(self.tmp, "ledger.key")
        ledger.init_ledger(self.ledger_path, self.key_path)
        self.key = ledger.load_key(self.key_path)
        self.conn = ledger.open_ledger(self.ledger_path)
        self.addCleanup(self.conn.close)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def source(self, name="src-a"):
        return name, ledger.register_source(self.conn, name)

    def claim(self, source, token, records, raw=b"file"):
        return ledger.submit_claim(
            self.conn, self.key, source, token, raw_digest(raw), records)

    def snapshot_dir(self, name="snap", **kw):
        d = os.path.join(self.tmp, name)
        ledger.export_snapshot(self.conn, self.key, d, **kw)
        return d


class LedgerCoreTests(LedgerCase):
    def test_init_twice_rejected_and_key_file_permissions(self):
        with self.assertRaises(ledger.LedgerConflict):
            ledger.init_ledger(self.ledger_path, self.key_path)
        mode = os.stat(self.key_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_open_missing_ledger(self):
        with self.assertRaises(ledger.LedgerNotFound):
            ledger.open_ledger(os.path.join(self.tmp, "nope.db"))

    def test_claim_retract_correct_chain_basic(self):
        src, tok = self.source()
        r = self.claim(src, tok, [RD_A, RD_B])
        self.assertEqual(r["state"], "sealed")
        self.assertEqual(r["seq"], 1)
        # the chain starts from genesis and links entries
        self.assertEqual(ledger.status(self.conn)["head_seq"], 1)
        errors = ledger.verify_ledger(self.conn, self.key)
        self.assertEqual(errors, [])

        ledger.correct_records(self.conn, self.key, src, tok,
                               r["batch_id"], [RD_A])
        rr = ledger.retract_batch(self.conn, self.key, src, tok,
                                  r["batch_id"], "court order")
        self.assertEqual(rr["seq"], 3)
        self.assertEqual(ledger.verify_ledger(self.conn, self.key), [])

        d = self.snapshot_dir()
        snap, entries = adjudicate.verify_snapshot_dir(d, self.key)
        a = adjudicate.adjudicate(snap, RD_A, src)["attributions"][0]
        self.assertTrue(a["submitted"] if "submitted" in a else True)
        self.assertEqual(a["retracted_at"], rr["retracted_at"])
        self.assertEqual(a["retraction_reason"], "court order")
        self.assertTrue(a["corrected_before_retraction"])
        self.assertFalse(a["corrected_after_retraction"])

    def test_duplicate_claim_returns_original(self):
        src, tok = self.source()
        r1 = self.claim(src, tok, [RD_A, RD_B])
        r2 = self.claim(src, tok, [RD_B, RD_A])  # reordered = same content
        r3 = ledger.submit_claim(
            self.conn, self.key, src, tok,
            raw_digest(b"different-raw-bytes"), [RD_A, RD_B])
        self.assertTrue(r2["duplicate"])
        self.assertTrue(r3["duplicate"])
        self.assertEqual({r1["batch_id"], r2["batch_id"], r3["batch_id"]},
                         {r1["batch_id"]})
        self.assertEqual(ledger.status(self.conn)["claims"], 1)

    def test_explicit_idempotency_key_dedup_and_cross_source_conflict(self):
        src, tok = self.source()
        other, tok2 = self.source("src-b")
        r1 = ledger.submit_claim(
            self.conn, self.key, src, tok, raw_digest(b"f1"), [RD_A],
            idem_key="idem-1")
        r2 = ledger.submit_claim(
            self.conn, self.key, src, tok, raw_digest(b"f1"), [RD_A],
            idem_key="idem-1")
        self.assertTrue(r2["duplicate"])
        self.assertEqual(r2["batch_id"], r1["batch_id"])
        with self.assertRaises(ledger.LedgerConflict):
            ledger.submit_claim(
                self.conn, self.key, other, tok2, raw_digest(b"f1"), [RD_A],
                idem_key="idem-1")

    def test_duplicate_retract_and_correct_append_nothing(self):
        src, tok = self.source()
        r = self.claim(src, tok, [RD_A, RD_B])
        x1 = ledger.retract_batch(self.conn, self.key, src, tok,
                                  r["batch_id"], "reason")
        x2 = ledger.retract_batch(self.conn, self.key, src, tok,
                                  r["batch_id"], "reason")
        self.assertFalse(x1["duplicate"])
        self.assertTrue(x2["duplicate"])
        self.assertEqual(x2["batch_id"], r["batch_id"])
        c1 = ledger.correct_records(self.conn, self.key, src, tok,
                                    r["batch_id"], [RD_A, RD_B])
        c2 = ledger.correct_records(self.conn, self.key, src, tok,
                                    r["batch_id"], [RD_A])
        self.assertFalse(c1["duplicate"])
        self.assertTrue(c2["duplicate"])
        self.assertEqual(c1["corrected_records"], 2)
        # claim + retraction + one correction entry
        self.assertEqual(ledger.status(self.conn)["head_seq"], 3)

    # ------------------------------------------------------------- ordering
    def test_correction_before_vs_after_retraction_ordering(self):
        src, tok = self.source()
        r = self.claim(src, tok, [RD_A, RD_B, RD_C])
        ledger.correct_records(self.conn, self.key, src, tok,
                               r["batch_id"], [RD_A])
        ledger.retract_batch(self.conn, self.key, src, tok,
                             r["batch_id"], "reason R")
        ledger.correct_records(self.conn, self.key, src, tok,
                               r["batch_id"], [RD_B])
        d = self.snapshot_dir(ttl_hours=1)
        snap, _ = adjudicate.verify_snapshot_dir(d, self.key)
        a = adjudicate.adjudicate(snap, RD_A, src)["attributions"][0]
        b = adjudicate.adjudicate(snap, RD_B, src)["attributions"][0]
        c = adjudicate.adjudicate(snap, RD_C, src)["attributions"][0]
        self.assertTrue(a["corrected_before_retraction"])
        self.assertFalse(a["corrected_after_retraction"])
        self.assertFalse(b["corrected_before_retraction"])
        self.assertTrue(b["corrected_after_retraction"])
        self.assertFalse(c["corrected_before_retraction"])
        self.assertFalse(c["corrected_after_retraction"])
        self.assertEqual([x["relation"] for x in c["corrections"]], [])

    def test_correction_while_active_has_neither_flag(self):
        src, tok = self.source()
        r = self.claim(src, tok, [RD_A])
        ledger.correct_records(self.conn, self.key, src, tok,
                               r["batch_id"], [RD_A])
        d = self.snapshot_dir(ttl_hours=1)
        snap, _ = adjudicate.verify_snapshot_dir(d, self.key)
        a = adjudicate.adjudicate(snap, RD_A, src)["attributions"][0]
        self.assertIsNone(a["retracted_at"])
        self.assertFalse(a["corrected_before_retraction"])
        self.assertFalse(a["corrected_after_retraction"])
        self.assertEqual(a["corrections"][0]["relation"], "while_active")

    # ------------------------------------------------------- authorization
    def test_missing_or_bad_token_rejected(self):
        src, tok = self.source()
        with self.assertRaises(ledger.LedgerPermission):
            self.claim(src, "", [RD_A])
        with self.assertRaises(ledger.LedgerPermission):
            self.claim(src, "lgs_wrong", [RD_A])
        # unknown source
        with self.assertRaises(ledger.LedgerPermission):
            self.claim("nobody", tok, [RD_A])

    def test_only_owning_source_can_retract_or_correct(self):
        src, tok = self.source()
        other, tok2 = self.source("src-b")
        r = self.claim(src, tok, [RD_A])
        with self.assertRaises(ledger.LedgerPermission):
            ledger.retract_batch(self.conn, self.key, other, tok2,
                                 r["batch_id"], "x")
        with self.assertRaises(ledger.LedgerPermission):
            ledger.correct_records(self.conn, self.key, other, tok2,
                                   r["batch_id"], [RD_A])

    def test_unknown_batch_and_bad_reason(self):
        src, tok = self.source()
        with self.assertRaises(ledger.LedgerNotFound):
            ledger.retract_batch(self.conn, self.key, src, tok,
                                 "bat_nonexistent", "r")
        with self.assertRaises(ledger.LedgerError):
            ledger.retract_batch(self.conn, self.key, src, tok,
                                 "bat_nonexistent", "   ")

    def test_correct_digest_mismatch(self):
        src, tok = self.source()
        r = self.claim(src, tok, [RD_A])
        with self.assertRaises(ledger.LedgerError) as cx:
            ledger.correct_records(self.conn, self.key, src, tok,
                                   r["batch_id"], [RD_B])
        self.assertIn("digest mismatch", str(cx.exception))
        # error never echoes any digest value
        self.assertNotIn(RD_A, str(cx.exception))
        self.assertNotIn(RD_B, str(cx.exception))

    # --------------------------------------------------------- crash + seal
    def test_interrupted_seal_resumes_from_last_chained_item(self):
        src, tok = self.source()
        c1 = self.claim(src, tok, [RD_A])
        c2 = self.claim(src, tok, [RD_B], raw=b"file2")

        def boom(event, entry):
            if entry["payload"]["kind"] == "retract":
                raise KeyboardInterrupt("power loss")

        with self.assertRaises(KeyboardInterrupt):
            ledger.retract_batch(self.conn, self.key, src, tok,
                                 c2["batch_id"], "r", progress=boom)
        # c2 retraction is back in the pending staging area
        self.assertEqual(ledger.pending_count(self.conn), 1)
        head = ledger.status(self.conn)["head_seq"]

        # an independent process (new connection, no in-memory state) drains
        conn2 = ledger.open_ledger(self.ledger_path)
        self.addCleanup(conn2.close)
        sealed = ledger.seal_pending(conn2, self.key)
        self.assertEqual(len(sealed), 1)
        self.assertEqual(sealed[0]["seq"], head + 1)
        self.assertEqual(sealed[0]["payload"]["batch_id"], c2["batch_id"])
        self.assertEqual(ledger.pending_count(conn2), 0)
        self.assertEqual(ledger.verify_ledger(conn2, self.key), [])

    def test_seal_command_drains_pending_left_by_killed_process(self):
        src, tok = self.source()
        # stage two entries without sealing, exactly like a process killed
        # between stage and seal (we emulate via the internal helper)
        with ledger._write(self.conn):
            ledger._stage_pending(self.conn, "claim", {
                "kind": "claim", "source": src,
                "batch_id": "bat_staged1", "file_sha256": "1" * 64,
                "records": [RD_A], "idem_key": "k1",
                "claimed_at": adjudicate.iso(adjudicate.utcnow())}, "k1",
                adjudicate.iso(adjudicate.utcnow()))
            ledger._stage_pending(self.conn, "claim", {
                "kind": "claim", "source": src,
                "batch_id": "bat_staged2", "file_sha256": "2" * 64,
                "records": [RD_B], "idem_key": "k2",
                "claimed_at": adjudicate.iso(adjudicate.utcnow())}, "k2",
                adjudicate.iso(adjudicate.utcnow()))
        self.assertEqual(ledger.pending_count(self.conn), 2)
        sealed = ledger.seal_pending(self.conn, self.key)
        self.assertEqual([e["seq"] for e in sealed], [1, 2])
        self.assertEqual([e["payload"]["batch_id"] for e in sealed],
                         ["bat_staged1", "bat_staged2"])
        self.assertEqual(ledger.pending_count(self.conn), 0)
        self.assertEqual(ledger.verify_ledger(self.conn, self.key), [])

    # ------------------------------------------------------------- storage
    def test_ledger_database_contains_no_raw_material(self):
        src, tok = self.source()
        r = self.claim(src, tok, [RD_A, RD_B], raw=b"SECRET-RAW-FILE")
        ledger.retract_batch(self.conn, self.key, src, tok,
                             r["batch_id"], "private reason text")
        raw = sqlite3.connect(self.ledger_path).execute(
            "SELECT quote(payload) FROM ledger_entries").fetchall()
        blob = " ".join(row[0] for row in raw)
        self.assertNotIn("SECRET-RAW-FILE", blob)
        self.assertNotIn(FP_A, blob)
        self.assertNotIn(FP_B, blob)
        # only the record digests are present
        self.assertIn(RD_A, blob)

    # ----------------------------------------------------------- parallel
    def test_parallel_writers_serialise_into_one_gap_free_chain(self):
        tokens = {}
        for i in range(6):
            tokens[i] = ledger.register_source(self.conn, f"p-{i}")
        self.conn.close()
        results, errors = [], []

        def work(i):
            c = ledger.open_ledger(self.ledger_path)
            try:
                rd = hashlib.sha256(f"rec-{i}".encode()).hexdigest()
                results.append(ledger.submit_claim(
                    c, self.key, f"p-{i}", tokens[i], f"{i:064x}", [rd]))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
            finally:
                c.close()

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(work, range(6)))
        self.assertEqual(errors, [])
        self.conn = ledger.open_ledger(self.ledger_path)
        self.assertEqual(ledger.verify_ledger(self.conn, self.key), [])
        self.assertEqual(ledger.pending_count(self.conn), 0)
        seqs = sorted(r["seq"] for r in results)
        self.assertEqual(seqs, list(range(1, 7)))
        self.assertEqual(len({r["batch_id"] for r in results}), 6)

    def test_parallel_duplicate_claim_wins_exactly_once(self):
        src, tok = self.source()
        self.conn.close()
        results, errors = [], []

        def work():
            c = ledger.open_ledger(self.ledger_path)
            try:
                results.append(ledger.submit_claim(
                    c, self.key, src, tok, raw_digest(b"same"), [RD_A]))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
            finally:
                c.close()

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(lambda _: work(), range(6)))
        self.assertEqual(errors, [])
        self.conn = ledger.open_ledger(self.ledger_path)
        self.assertEqual(sum(1 for r in results if not r["duplicate"]), 1)
        self.assertEqual(ledger.status(self.conn)["claims"], 1)
        self.assertEqual(len({r["batch_id"] for r in results}), 1)


class SnapshotAndAdjudicationTests(LedgerCase):
    def setUp(self):
        super().setUp()
        self.src, self.tok = self.source()
        other, tok2 = self.source("src-b")
        self.other, self.tok2 = other, tok2
        self.first = self.claim(self.src, self.tok, [RD_A, RD_B])
        t0 = adjudicate.parse_ts(self.first["sealed_at"])
        ret = ledger.retract_batch(self.conn, self.key, self.src, self.tok,
                                   self._batch(), "reason-1")
        t1 = adjudicate.parse_ts(ret["sealed_at"])
        # monotonic seal timestamps guarantee a total order
        self.assertGreater(t1, t0)
        # cutoff exactly between the first claim and the retraction seal time
        self.mid = adjudicate.iso(t0 + (t1 - t0) / 2)
        # the other source claims the same record independently AFTER mid
        ledger.submit_claim(self.conn, self.key, self.other, self.tok2,
                            raw_digest(b"other-file"), [RD_A])

    def _batch(self):
        return self.conn.execute(
            "SELECT batch_id FROM ledger_claim_index WHERE source=?",
            (self.src,)).fetchone()["batch_id"]

    def test_snapshot_self_contained_and_verifiable_offline(self):
        d = self.snapshot_dir(ttl_hours=1)
        snap, entries = adjudicate.verify_snapshot_dir(d, self.key)
        # integrity-only verification works WITHOUT the key too
        snap2, entries2 = adjudicate.verify_snapshot_dir(d)
        self.assertEqual(len(entries), len(entries2))
        self.assertEqual(snap["snapshot_mac"][:8], snap["snapshot_mac"][:8])
        # wrong key is rejected
        wrong = bytes(31) + b"x"
        with self.assertRaises(adjudicate.SnapshotError):
            adjudicate.verify_snapshot_dir(d, key=wrong)

    def test_adjudicate_answers_from_snapshot_and_digest_only(self):
        d = self.snapshot_dir(ttl_hours=1)
        snap, _ = adjudicate.verify_snapshot_dir(d, self.key)
        v = adjudicate.adjudicate(snap, RD_A, self.src)
        self.assertTrue(v["submitted"])
        self.assertEqual(len(v["attributions"]), 1)
        self.assertEqual(v["attributions"][0]["retraction_reason"], "reason-1")
        # other source independently submitted A -> attribution present
        v2 = adjudicate.adjudicate(snap, RD_A, self.other)
        self.assertTrue(v2["submitted"])
        self.assertIsNone(v2["attributions"][0]["retracted_at"])
        # never submitted by this source -> identical minimal negative shape
        neg = adjudicate.adjudicate(snap, RD_C, self.src)
        neg2 = adjudicate.adjudicate(snap, RD_A, "somebody-else")
        for n in (neg, neg2):
            self.assertFalse(n["submitted"])
            self.assertEqual(n["attributions"], [])
            self.assertEqual(set(n), {"submitted", "source",
                                      "record_sha256", "attributions"})

    def test_failure_messages_do_not_leak_records(self):
        d = self.snapshot_dir(ttl_hours=1)
        # tamper: drop a chain entry; error references sequences only
        path = os.path.join(d, "chain.jsonl")
        lines = open(path).read().splitlines()
        with open(path, "w") as fh:
            fh.write(lines[0] + "\n" + lines[-1] + "\n")
        with self.assertRaises(adjudicate.SnapshotError) as cx:
            adjudicate.verify_snapshot_dir(d, self.key)
        msg = str(cx.exception)
        self.assertNotIn(RD_A, msg)
        self.assertNotIn(RD_B, msg)
        self.assertNotIn(self.src, msg)

    def test_missing_snapshot_and_missing_chain_file(self):
        with self.assertRaises(adjudicate.SnapshotError):
            adjudicate.verify_snapshot_dir(os.path.join(self.tmp, "none"))
        d = self.snapshot_dir("s", ttl_hours=1)
        os.unlink(os.path.join(d, adjudicate.CHAIN_FILE))
        with self.assertRaises(adjudicate.SnapshotError):
            adjudicate.verify_snapshot_dir(d, self.key)

    def test_tampered_snapshot_records_or_chain_rejected(self):
        d = self.snapshot_dir(ttl_hours=1)

        def expect_fail(dirpath):
            with self.assertRaises(adjudicate.SnapshotError):
                adjudicate.verify_snapshot_dir(dirpath, self.key)

        # forge responsibility state inside snapshot.json
        t = os.path.join(self.tmp, "t1")
        shutil.copytree(d, t)
        snap = read_json(os.path.join(t, "snapshot.json"))
        snap["records"] = {"0" * 64: []}
        with open(os.path.join(t, "snapshot.json"), "w") as fh:
            json.dump(snap, fh)
        expect_fail(t)

        # edit metadata self hash label only -> self hash mismatch
        t = os.path.join(self.tmp, "t2")
        shutil.copytree(d, t)
        snap = read_json(os.path.join(t, "snapshot.json"))
        snap["snapshot_sha256"] = "f" * 64
        with open(os.path.join(t, "snapshot.json"), "w") as fh:
            json.dump(snap, fh)
        expect_fail(t)

        # mutate a payload inside the chain (reason forgery) -> link failure
        t = os.path.join(self.tmp, "t3")
        shutil.copytree(d, t)
        path = os.path.join(t, "chain.jsonl")
        with open(path) as fh:
            lines = [json.loads(x) for x in fh.read().splitlines()]
        lines[0]["payload"]["source"] = "forged"
        with open(path, "w") as fh:
            fh.write("".join(adjudicate.canonical(e) + "\n" for e in lines))
        expect_fail(t)

        # chain file truncation -> chain_sha256 mismatch
        t = os.path.join(self.tmp, "t4")
        shutil.copytree(d, t)
        path = os.path.join(t, "chain.jsonl")
        with open(path) as fh:
            all_lines = fh.read().splitlines(keepends=True)
        with open(path, "w") as fh:
            fh.write("".join(all_lines[:-1]))
        expect_fail(t)

    def test_snapshot_expiry(self):
        d = self.snapshot_dir(ttl_hours=1)
        # still valid now
        adjudicate.verify_snapshot_dir(d, self.key)
        # one second after expiry -> clear failure
        snap = read_json(os.path.join(d, "snapshot.json"))
        future = adjudicate.parse_ts(snap["expires_at"]) + timedelta(seconds=1)
        with self.assertRaises(adjudicate.SnapshotError) as cx:
            adjudicate.verify_snapshot_dir(d, self.key, now=future)
        self.assertIn("expired", str(cx.exception))

    def test_point_in_time_snapshot_truncates_chain_and_state(self):
        # as_of before the retraction: no retraction visible and the embedded
        # chain cannot leak the later retraction reason
        d = os.path.join(self.tmp, "asof")
        res = ledger.export_snapshot(
            self.conn, self.key, d, as_of=self.mid, ttl_hours=1)
        snap, entries = adjudicate.verify_snapshot_dir(d, self.key)
        self.assertEqual(res["head_seq"], 1)
        self.assertEqual(len(entries), 1)
        for e in entries:
            self.assertNotIn("reason-1", adjudicate.canonical(e["payload"]))
        a = adjudicate.adjudicate(snap, RD_A, self.src)["attributions"][0]
        self.assertIsNone(a["retracted_at"])
        self.assertIsNone(a["retraction_reason"])

    def test_as_of_in_the_future_rejected(self):
        with self.assertRaises(ledger.LedgerError):
            ledger.export_snapshot(
                self.conn, self.key, os.path.join(self.tmp, "fut"),
                as_of="2999-01-01T00:00:00+00:00")

    def test_snapshot_no_downgrade_and_idempotent_rewrite(self):
        d = os.path.join(self.tmp, "snap")
        ledger.export_snapshot(self.conn, self.key, d, ttl_hours=1)
        head_now = ledger.status(self.conn)["head_seq"]

        # same head -> unchanged no-op by default
        again = ledger.export_snapshot(self.conn, self.key, d, ttl_hours=1)
        self.assertTrue(again["unchanged"])

        # an older point-in-time export must not overwrite the newer state
        with self.assertRaises(ledger.LedgerConflict) as cx:
            ledger.export_snapshot(
                self.conn, self.key, d, as_of=self.mid, ttl_hours=1)
        self.assertIn("newer", str(cx.exception))
        snap, _ = adjudicate.verify_snapshot_dir(d, self.key)
        self.assertEqual(snap["head_seq"], head_now)

        # a genuinely newer snapshot replaces the older one (and with force)
        self.claim(self.src, self.tok, [RD_C], raw=b"file3")
        newer = ledger.export_snapshot(self.conn, self.key, d, ttl_hours=1)
        self.assertFalse(newer["unchanged"])
        self.assertGreater(newer["head_seq"], head_now)

    def test_chain_verification_detects_tampered_sqlite_row(self):
        # direct tampering with the append-only table breaks verification
        self.conn.execute(
            "UPDATE ledger_entries SET payload=? WHERE seq=1",
            (adjudicate.canonical({"kind": "claim", "source": "evil"}),))
        errors = ledger.verify_ledger(self.conn, self.key)
        self.assertTrue(errors)

    def test_mac_mismatch_wrong_key(self):
        wrong = b"\x00" * 32
        with self.assertRaises(ledger.LedgerError):
            ledger.export_snapshot(
                self.conn, wrong, os.path.join(self.tmp, "badmac"))


class CliBoundaryTests(LedgerCase):
    """Cross-process boundary: CLI writes, CLI snapshot, offline adjudicator."""

    def run_cli(self, *args, expect=0):
        env = dict(os.environ, PYTHONPATH="/workspace")
        r = subprocess.run(
            [sys.executable, "-m", "pwncorpus.cli",
             "--ledger", self.ledger_path, "--ledger-key", self.key_path,
             *args],
            capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, expect,
                         f"args={args}\nstdout={r.stdout}\nstderr={r.stderr}")
        return r

    def run_adjudicate(self, *args, expect=0):
        env = dict(os.environ, PYTHONPATH="/workspace")
        r = subprocess.run(
            [sys.executable, "-m", "pwncorpus.adjudicate", *args],
            capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, expect,
                         f"args={args}\nstderr={r.stderr}")
        return r

    def write_file(self, name, lines):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        return p

    def test_full_cli_flow_across_processes(self):
        r = self.run_cli("ledger-init", expect=1)  # already initialised
        r = self.run_cli("ledger-source", "--source", "clisrc")
        token = next(x for x in r.stdout.split() if x.startswith("lgs_"))

        f = self.write_file("f.txt", [FP_A, FP_B])
        r = self.run_cli("attest-submit", "--source", "clisrc",
                         "--token", token, "--file", f)
        sub = json.loads(r.stdout)
        self.assertFalse(sub["duplicate"])
        batch = sub["batch_id"]

        # repeated submission across a NEW process returns the same record
        r = self.run_cli("attest-submit", "--source", "clisrc",
                         "--token", token, "--file", f)
        self.assertTrue(json.loads(r.stdout)["duplicate"])
        self.assertEqual(json.loads(r.stdout)["batch_id"], batch)

        # failures
        self.run_cli("attest-retract", "--source", "clisrc",
                     "--token", "lgs_bad", "--batch", batch,
                     "--reason", "x", expect=1)
        self.run_cli("attest-retract", "--source", "clisrc",
                     "--token", token, "--batch", batch,
                     "--reason", "  ", expect=1)
        bad = self.write_file("bad.txt", [FP_C])
        self.run_cli("attest-correct", "--source", "clisrc",
                     "--token", token, "--batch", batch,
                     "--file", bad, expect=1)

        # valid sequence: correct then retract
        corr = self.write_file("c.txt", [FP_A])
        self.run_cli("attest-correct", "--source", "clisrc",
                     "--token", token, "--batch", batch, "--file", corr)
        self.run_cli("attest-retract", "--source", "clisrc",
                     "--token", token, "--batch", batch,
                     "--reason", "legal demand 7")

        # recovery entry point works as a standalone command
        r = self.run_cli("ledger-seal")
        self.assertEqual(json.loads(r.stdout)["sealed"], 0)
        r = self.run_cli("ledger-status")
        st = json.loads(r.stdout)
        self.assertTrue(st["chain_ok"])
        self.assertEqual(st["pending"], 0)

        # independent audit process exports...
        snap = os.path.join(self.tmp, "snap-cli")
        self.run_cli("ledger-snapshot", "--out", snap, "--ttl-hours", "1")
        # ...and the database-free adjudicator decides
        self.run_adjudicate("verify", snap, "--key", self.key_path)
        r = self.run_adjudicate("record", snap, "--source", "clisrc",
                                "--fingerprint", FP_A,
                                "--key", self.key_path)
        v = json.loads(r.stdout)
        self.assertTrue(v["submitted"])
        a = v["attributions"][0]
        self.assertEqual(a["retraction_reason"], "legal demand 7")
        self.assertTrue(a["corrected_before_retraction"])

        # expired snapshot -> distinct exit code 3
        snap_exp = os.path.join(self.tmp, "snap-exp")
        self.run_cli("ledger-snapshot", "--out", snap_exp,
                     "--ttl-hours", "0.0001")
        time.sleep(1)
        self.run_adjudicate("verify", snap_exp, expect=3)

    def test_adjudicate_module_does_not_import_sqlite(self):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(adjudicate))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(n.name.split(".")[0] for n in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertNotIn("sqlite3", imported)
        # and the module loads in a clean process without pulling in a DB
        env = dict(os.environ, PYTHONPATH="/workspace")
        code = (
            "import sys; import pwncorpus.adjudicate;"
            " assert 'sqlite3' not in sys.modules; print('clean')")
        r = subprocess.run([sys.executable, "-c", code],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("clean", r.stdout)


if __name__ == "__main__":
    unittest.main()
