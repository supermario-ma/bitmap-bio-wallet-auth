import sqlite3
import time
import unittest
from unittest.mock import patch
from tests.test_lord_bio_backend import LordBioBackendTests
import lord_bio
import lord_bio_auth as auth

ADDRESS="bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler"
ORIGIN="https://bitmap.bio"

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
