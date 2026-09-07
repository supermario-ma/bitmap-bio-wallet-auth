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
