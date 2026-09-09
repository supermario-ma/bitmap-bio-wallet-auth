import os
import sqlite3
import time
import unittest
from unittest.mock import patch
from tests.test_lord_bio_backend import LordBioBackendTests
import lord_bio
import lord_bio_auth as auth

ADDRESS="bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler"
# Public BIP322 vector (tests/fixtures/bip322/generated.json), wire format:
# wallets send plain base64, so the fixture type tag is stripped here.
P2WPKH_ADDRESS="bc1qqthe0hz8klx90e7stf6shclhsvqd5ly96pn53v"
P2WPKH_MESSAGE="2V6TUTMSH4VQ3Z7WZWKYD7DFNH"
P2WPKH_SIGNATURE=("AkgwRQIhALC6hdfxNy1n45d7UXSskRBdfZW0Al259E1kDMpipdYkAiAJPfZqb+WurZuf1apU5xeE"
                  "6Igui9dvt5tihQLDvxlY1AEhAqbnruyo677ktQjio7XOchO3w51Dh9AbRVngha5jtNfT")
ORIGIN="https://bitmap.bio"
ALLOWED=sorted(auth.ALLOWED_ORIGINS)

class AuthTests(unittest.TestCase):
    def setUp(self):
        LordBioBackendTests.setUp(self)
        private=auth.private_directory(self.root)
        private.mkdir(parents=True,exist_ok=True)
        (private/'bio-wallet-ready-v1').touch()
        con=sqlite3.connect(self.db);con.execute("UPDATE bitmap_registry SET owner_address=?",(ADDRESS,));con.commit();con.close()

    def tearDown(self):
        self.temp.cleanup()

    def call(self,action,payload,token="",origin=ORIGIN,resolver=None):
        return auth.handle(self.root,self.db,self.root,1688,action,payload,origin,"Bearer "+token if token else "","203.0.113.5",resolver)

    def login(self):
        status,c=self.call("challenge",{"address":ADDRESS});self.assertEqual(status,200)
        with patch.object(auth.bio_signature,"verify",return_value=True) as verify:
            status,s=self.call("verify",{"nonce":c["nonce"],"signature":"unit-test-proof"})
            verify.assert_called_once_with(ADDRESS,c["message"],"unit-test-proof")
        self.assertEqual(status,200)
        return c,s

    def test_native_segwit_login_runs_through_the_real_verifier(self):
        """Every other authenticated test stubs bio_signature.verify. This one
        must not: it is the only cover for the bc1q path through handle(), and
        it fails on any host where hashlib cannot compute RIPEMD160."""
        con = sqlite3.connect(self.db)
        con.execute("UPDATE bitmap_registry SET owner_address=?", (P2WPKH_ADDRESS,))
        con.commit(); con.close()
        status, challenge = self.call("challenge", {"address": P2WPKH_ADDRESS})
        self.assertEqual(status, 200)
        # Swap in a message the fixture key really signed; everything else -
        # single use, expiry, owner re-check, session issue - stays live.
        con = sqlite3.connect(self.db)
        con.execute("UPDATE lord_bio_challenges SET message=? WHERE nonce=?", (P2WPKH_MESSAGE, challenge["nonce"]))
        con.commit(); con.close()
        status, session = self.call("verify", {"nonce": challenge["nonce"], "signature": P2WPKH_SIGNATURE})
        self.assertEqual(status, 200, session.get("error"))
        self.assertEqual(session["lord"], P2WPKH_ADDRESS)
        self.assertEqual(self.call("save", {"name": "Native SegWit lord"}, session["token"])[0], 200)

    def test_real_verifier_rejects_a_signature_from_another_address(self):
        con = sqlite3.connect(self.db)
        con.execute("UPDATE bitmap_registry SET owner_address=?", (ADDRESS,))
        con.commit(); con.close()
        status, challenge = self.call("challenge", {"address": ADDRESS})
        self.assertEqual(status, 200)
        con = sqlite3.connect(self.db)
        con.execute("UPDATE lord_bio_challenges SET message=? WHERE nonce=?", (P2WPKH_MESSAGE, challenge["nonce"]))
        con.commit(); con.close()
        self.assertEqual(self.call("verify", {"nonce": challenge["nonce"], "signature": P2WPKH_SIGNATURE})[0], 403)

    def _counting_resolver(self):
        seen=[]
        def resolver(number):
            seen.append(number)
            return {"asset_url":"/storage/ads/offline/cached.webp","inscription_number":int(number)}
        return seen,resolver

    def test_image_lookups_are_capped_per_lord(self):
        """One Lord must not be able to drain the site-wide Ordiscan budget."""
        seen,resolver=self._counting_resolver()
        _,s=self.login()
        for number in range(1,auth.ASSET_LOOKUPS_PER_DAY+1):
            self.assertEqual(self.call("avatar",{"avatar_number":str(number)},s["token"],resolver=resolver)[0],200)
        status,body=self.call("avatar",{"avatar_number":"9999"},s["token"],resolver=resolver)
        self.assertEqual(status,429)
        self.assertIn("image lookup limit",body["error"])
        # The refused attempt must not reach the upstream API at all.
        self.assertEqual(len(seen),auth.ASSET_LOOKUPS_PER_DAY)

    def test_save_cooldown_is_checked_before_the_image_lookup(self):
        seen,resolver=self._counting_resolver()
        _,s=self.login()
        self.assertEqual(self.call("save",{"name":"first","avatar_number":"2","social":{}},s["token"],resolver=resolver)[0],200)
        self.assertEqual(self.call("save",{"name":"second","avatar_number":"3","social":{}},s["token"],resolver=resolver)[0],429)
        self.assertEqual(seen,["2"])  # the rate-limited save spent no lookup

    def test_session_only_authorises_the_bitmap_that_was_signed_for(self):
        """The message reads 'Bitmap: n.bitmap', so the session must mean only
        that Bitmap - even for another Bitmap the same address owns."""
        _,s=self.login()
        self.assertEqual(s["bitmap"],1688)
        self.assertEqual(self.call("save",{"name":"ok","social":{}},s["token"])[0],200)
        other=auth.handle(self.root,self.db,self.root,9001,"save",{"name":"nope","social":{}},
                          ORIGIN,"Bearer "+s["token"],"203.0.113.5",None)
        self.assertEqual(other[0],403)
        self.assertIsNone(auth.verified_owner(self.db,9001,"Bearer "+s["token"],ORIGIN))
        self.assertEqual(auth.verified_owner(self.db,1688,"Bearer "+s["token"],ORIGIN),ADDRESS)

    def test_sessions_predating_the_bitmap_binding_stop_authorising(self):
        _,s=self.login()
        con=sqlite3.connect(self.db)
        con.execute("UPDATE lord_bio_sessions SET bitmap_number=-1")  # pre-upgrade row
        con.commit();con.close()
        self.assertEqual(self.call("save",{"name":"nope","social":{}},s["token"])[0],403)

    def test_logout_revokes_the_session_immediately(self):
        _,s=self.login()
        self.assertEqual(self.call("save",{"name":"ok","social":{}},s["token"])[0],200)
        self.assertEqual(self.call("logout",{},s["token"])[0],200)
        self.assertEqual(self.call("save",{"name":"no","social":{}},s["token"])[0],403)
        con=sqlite3.connect(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM lord_bio_sessions").fetchone()[0],0)
        con.close()

    def test_logout_reports_success_without_a_usable_token(self):
        """A caller must not be able to tell a live token from a dead one."""
        self.assertEqual(self.call("logout",{})[0],200)
        self.assertEqual(self.call("logout",{},"not-a-real-token")[0],200)
        _,s=self.login()
        self.assertEqual(self.call("logout",{},s["token"])[0],200)
        self.assertEqual(self.call("logout",{},s["token"])[0],200)

    def test_logout_still_works_after_the_bitmap_changed_owner(self):
        _,s=self.login()
        con=sqlite3.connect(self.db)
        con.execute("UPDATE bitmap_registry SET owner_address='changed' WHERE bitmap_number=1688")
        con.commit();con.close()
        self.assertEqual(self.call("logout",{},s["token"])[0],200)
        con=sqlite3.connect(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM lord_bio_sessions").fetchone()[0],0)
        con.close()

    def test_loopback_origins_require_an_explicit_opt_in(self):
        """The bypass used to key on os.name, so a Windows host silently
        accepted any loopback origin. It must key on an operator decision."""
        environment = dict(os.environ)
        environment.pop("BITMAPADS_DEV_ORIGINS", None)
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaises(ValueError): auth._origin("http://localhost:8000")
            with self.assertRaises(ValueError): auth._origin("http://127.0.0.1:5173")
            self.assertEqual(self.call("challenge",{"address":ADDRESS},origin="http://localhost:8000")[0],400)
        with patch.dict(os.environ, {"BITMAPADS_DEV_ORIGINS":"1"}):
            self.assertEqual(auth._origin("http://localhost:8000"),"http://localhost:8000")
            self.assertEqual(auth._origin("http://127.0.0.1:5173"),"http://127.0.0.1:5173")
            for value in (None,"","http://evil.example:8000","https://localhost:8000","http://localhost.evil.test:80"):
                with self.assertRaises(ValueError): auth._origin(value)
        for value in ALLOWED:  # the real origins never depend on the flag
            self.assertEqual(auth._origin(value),value)

    def test_signature_replay_origin_expiry_and_wrong_owner(self):
        self.assertEqual(self.call("challenge",{"address":"wrong"})[0],403)
        self.assertEqual(self.call("challenge",{"address":ADDRESS},origin="https://evil.example")[0],400)
        c,s=self.login()
        self.assertEqual(self.call("verify",{"nonce":c["nonce"],"signature":"unit-test-proof"})[0],403)
        self.assertEqual(self.call("save",{},s["token"],origin="https://bitmapads.com")[0],403)
        con=sqlite3.connect(self.db);con.execute("UPDATE lord_bio_sessions SET expires_at=?",(int(time.time())-1,));con.commit();con.close()
        self.assertEqual(self.call("save",{},s["token"])[0],403)

    def test_invalid_signature_never_authenticates_and_consumes_challenge(self):
        _,c=self.call("challenge",{"address":ADDRESS})
        self.assertEqual(self.call("verify",{"nonce":c["nonce"],"signature":"bad"})[0],403)
        with patch.object(auth.bio_signature,"verify",return_value=True) as verify:
            self.assertEqual(self.call("verify",{"nonce":c["nonce"],"signature":"bad"})[0],403)
            verify.assert_not_called()

    def test_avatar_only_after_auth_and_same_resolver_saves_number_not_external_url(self):
        resolver=lambda n:{"asset_url":"/storage/ads/offline/cached.webp","inscription_number":int(n)}
        self.assertEqual(self.call("avatar",{"avatar_number":"2"},resolver=resolver)[0],403)
        _,s=self.login()
        self.assertEqual(self.call("avatar",{"avatar_number":"https://evil.example/x.png"},s["token"],resolver=resolver)[0],400)
        self.assertEqual(self.call("avatar",{"avatar_number":"2"},s["token"],resolver=resolver)[0],200)
        status,result=self.call("save",{"name":"A lord","bio":"中文简介","avatar_number":"2","social":{"x":"https://x.com/bitmapads"}},s["token"],resolver=resolver)
        self.assertEqual(status,200);self.assertEqual(result["profile"]["avatar_number"],2)
        self.assertEqual(lord_bio.get_bio(self.db,1688)[1]["profile"]["bio"],"中文简介")
        con=sqlite3.connect(self.db);con.execute("UPDATE bitmap_registry SET owner_address='changed' WHERE bitmap_number=1688");con.commit();con.close()
        self.assertEqual(self.call("save",{},s["token"])[0],403)
        self.assertFalse(lord_bio.get_bio(self.db,1688)[1]["profile"]["avatar_url"])

    def test_links_and_query_values_cannot_bypass_rules(self):
        _,s=self.login()
        for url in ("javascript:alert(1)","https://x.com.evil.test/a","https://user:pass@x.com/a"):
            self.assertEqual(self.call("save",{"social":{"x":url}},s["token"])[0],400)

    def test_schema_upgrade_does_not_drop_existing_profile_or_holdings(self):
        lord_bio.get_bio(self.db,1688)
        con=sqlite3.connect(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM bitmap_registry").fetchone()[0],3)
        self.assertIn("avatar_number",{r[1] for r in con.execute("PRAGMA table_info(lord_bio_profiles)")})
        con.close()
