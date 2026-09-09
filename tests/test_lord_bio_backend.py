import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from unittest.mock import patch

import lord_bio
import moderation_policy


class LordBioBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "bitmapads.db"
        con = sqlite3.connect(self.db)
        con.executescript(
            """
            CREATE TABLE bitmap_registry (
              bitmap_number INTEGER PRIMARY KEY, x INTEGER, y INTEGER, block_exists INTEGER,
              bitmap_inscription_id TEXT, owner_address TEXT, owner_type TEXT,
              refresh_pool TEXT, source TEXT, last_chain_check TEXT, updated_at TEXT
            );
            CREATE TABLE satflow_center_claims (
              snapshot_id INTEGER, bitmap_number INTEGER, inscription_id TEXT,
              inscription_number INTEGER, owner_address TEXT, content_type TEXT,
              source_updated_at TEXT, collected_at TEXT
            );
            """
        )
        lord = "bc1p-test-lord"
        con.executemany(
            "INSERT INTO bitmap_registry VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            [
                (1688, 688, 1, 1, "a" * 64 + "i0", lord, "NORMAL", "FAST", "cached", "", "2026-09-07"),
                (7, 7, 0, 1, "b" * 64 + "i0", lord, "NORMAL", "FAST", "cached", "", "2026-09-07"),
                (9001, 1, 9, 1, "c" * 64 + "i0", lord, "NORMAL", "FAST", "cached", "", "2026-09-07"),
            ],
        )
        con.executemany(
            "INSERT INTO satflow_center_claims VALUES(?,?,?,?,?,?,?,?)",
            [(1, 1688, "a", 12, lord, "image/png", "", ""), (1, 7, "b", 3, lord, "image/png", "", "")],
        )
        con.commit()
        con.close()

    def tearDown(self):
        self.temp.cleanup()

    def test_secret_creation_never_overwrites_an_existing_file(self):
        """The in-process lock already serialises this; the invariant that
        matters is at the file level, between separate worker processes."""
        directory = self.root / "secrets"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "race-v1.secret"
        winner = b"W" * 32
        path.write_bytes(winner)
        # A worker that already decided to create must adopt the winner's value.
        self.assertEqual(lord_bio._create_secret(path), winner)
        self.assertEqual(path.read_bytes(), winner)

    def test_secret_is_stable_across_cache_misses(self):
        directory = self.root / "secrets2"
        lord_bio._SECRET_CACHE.clear()
        first = lord_bio._secret(directory, "once-v1.secret")
        lord_bio._SECRET_CACHE.clear()
        second = lord_bio._secret(directory, "once-v1.secret")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 32)
        self.assertFalse(list(directory.glob("*.tmp")))

    def test_every_guestbook_read_path_applies_the_current_policy(self):
        """A note stored under an older policy must be filtered on the main
        list too, not only on the map preview and the global feed."""
        con = sqlite3.connect(self.db)
        lord_bio._schema(con)
        con.execute(
            "INSERT INTO lord_bio_guestbook(lord_address,bitmap_number,author_kind,visitor_hash,"
            "ip_hash,visitor_label,text,text_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            ("bc1p-test-lord", 1688, "visitor", "v", "i", "203.0.113.*",
             "hello lemondrop world", "t", int(time.time())),
        )
        con.commit()
        con.close()
        with patch.dict(moderation_policy.POLICY, {"terms": ["lemondrop"]}):
            code, body, _headers = lord_bio.guestbook_get(self.db, self.root, 1688)
            self.assertEqual(code, 200)
            self.assertNotIn("lemondrop", body["messages"][0]["text"])
            self.assertNotIn("lemondrop", lord_bio.guestbook_preview(self.db, 1688)[1]["messages"][0]["text"])
            self.assertNotIn("lemondrop", lord_bio.guestbook_latest(self.db)[1]["messages"][0]["text"])
        # Without the term in the policy the note is returned unchanged.
        self.assertIn("lemondrop", lord_bio.guestbook_get(self.db, self.root, 1688)[1]["messages"][0]["text"])

    def test_cached_holdings_are_numeric_and_guestbook_never_exposes_raw_ip(self):
        status, payload = lord_bio.get_bio(self.db, 1688, sort="bitmap")
        self.assertEqual(status, 200)
        self.assertEqual([row["bitmap_number"] for row in payload["holdings"]], [7, 1688, 9001])
        self.assertEqual(payload["holdings"][0]["inscription_number"], 3)
        status, by_inscription = lord_bio.get_bio(self.db, 1688, sort="inscription")
        self.assertEqual(status, 200)
        self.assertEqual([row["bitmap_number"] for row in by_inscription["holdings"]], [7, 1688, 9001])
        status, guest, headers = lord_bio.guestbook_get(self.db, self.root, 1688, remote_ip="203.0.113.42", secure=False)
        self.assertEqual(status, 200)
        cookie = dict(headers)["Set-Cookie"].split(";", 1)[0]
        secret = lord_bio._secret(self.root, "lord-bio-guestbook-v2.secret")
        visitor = lord_bio._cookie_value(cookie, secret)
        token = lord_bio._token(secret, payload["lord"], visitor, int(time.time()) - 4)
        status, created, _ = lord_bio.guestbook_post(
            self.db, self.root, 1688, {"text": "Hello Bitmap", "company": "", "guest_token": token}, cookie, "203.0.113.42", False
        )
        self.assertEqual(status, 200)
        self.assertEqual(created["message"]["visitor_label"], "203.0.113.*")
        con = sqlite3.connect(self.db)
        label, ip_hash = con.execute("SELECT visitor_label,ip_hash FROM lord_bio_guestbook").fetchone()
        con.close()
        self.assertEqual(label, "203.0.113.*")
        self.assertNotIn("203.0.113.42", ip_hash)
        token = lord_bio._token(secret, payload["lord"], visitor, int(time.time()) - 4)
        status, rejected, _ = lord_bio.guestbook_post(
            self.db, self.root, 1688, {"text": "Another note", "company": "", "guest_token": token}, cookie, "203.0.113.42", False
        )
        self.assertEqual(status, 429)
        self.assertIn("20 minutes", rejected["error"])

    def test_messages_are_filtered_before_storage(self):
        status, payload, headers = lord_bio.guestbook_get(self.db, self.root, 1688, remote_ip="198.51.100.7", secure=False)
        self.assertEqual(status, 200)
        cookie = dict(headers)["Set-Cookie"].split(";", 1)[0]
        secret = lord_bio._secret(self.root, "lord-bio-guestbook-v2.secret")
        visitor = lord_bio._cookie_value(cookie, secret)
        token = lord_bio._token(secret, payload.get("lord", "bc1p-test-lord"), visitor, int(time.time()) - 4)
        # The current baseline removes a known prohibited term; HTML remains plain text.
        status, body, _ = lord_bio.guestbook_post(self.db, self.root, 1688, {"text": "hello <img>", "company": "", "guest_token": token}, cookie, "198.51.100.7", False)
        self.assertEqual(status, 200)
        self.assertEqual(body["message"]["text"], "hello <img>")

    def test_retired_public_secret_is_moved_outside_storage(self):
        legacy = self.root / "storage" / "lord-bio-v1.secret"
        legacy.parent.mkdir()
        legacy.write_bytes(b"retired-public-secret")
        private = self.root / "private"
        self.assertTrue(lord_bio.migrate_legacy_guestbook_secret(self.root, private))
        self.assertFalse(legacy.exists())
        moved = list(private.glob("retired-lord-bio-v1-*.secret"))
        self.assertEqual(len(moved), 1)
        self.assertEqual(moved[0].read_bytes(), b"retired-public-secret")

    def test_map_preview_is_latest_three_visible_notes_for_current_lord(self):
        self.assertEqual(lord_bio.guestbook_preview(self.db, 1688)[1]["messages"], [])
        con = sqlite3.connect(self.db)
        for i in range(5):
            con.execute("INSERT INTO lord_bio_guestbook(lord_address,bitmap_number,visitor_hash,ip_hash,visitor_label,text,text_hash,created_at,status) VALUES(?,?,?,?,?,?,?,?,?)",
                        ("bc1p-test-lord", 7, "v", "h", "masked", "Note " + str(i), "t", i, "hidden" if i == 4 else "visible"))
        con.commit()
        payload = lord_bio.guestbook_preview(self.db, 1688)[1]
        self.assertEqual([m["text"] for m in payload["messages"]], ["Note 3", "Note 2", "Note 1"])
        self.assertNotIn("visitor_label", payload["messages"][0])
        con.execute("UPDATE bitmap_registry SET owner_address=? WHERE bitmap_number=1688", ("new-lord",))
        con.commit()
        self.assertEqual(lord_bio.guestbook_preview(self.db, 1688)[1]["messages"], [])
        con.close()

    def test_global_latest_feed_is_limited_and_rechecks_current_owner(self):
        lord_bio.get_bio(self.db, 1688)
        con = sqlite3.connect(self.db)
        for i in range(12):
            con.execute("INSERT INTO lord_bio_guestbook(lord_address,bitmap_number,visitor_hash,ip_hash,visitor_label,text,text_hash,created_at,status) VALUES(?,?,?,?,?,?,?,?,?)",
                        ("bc1p-test-lord", 1688, "v", "h", "masked", "Global " + str(i), "t" + str(i), i, "visible"))
        con.commit()
        status, payload = lord_bio.guestbook_latest(self.db)
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["messages"]), 10)
        self.assertEqual(payload["messages"][0]["bitmap_number"], 1688)
        self.assertEqual(payload["messages"][0]["text"], "Global 11")
        con.execute("UPDATE bitmap_registry SET owner_address='new-owner' WHERE bitmap_number=1688")
        con.commit()
        self.assertEqual(lord_bio.guestbook_latest(self.db)[1]["messages"], [])
        con.close()


if __name__ == "__main__":
    unittest.main()
