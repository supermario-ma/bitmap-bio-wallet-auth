import hashlib
import json
import os
import unittest
from unittest.mock import patch
from pathlib import Path
import bio_signature as sig

class SignatureTests(unittest.TestCase):
    def test_official_vectors_and_wrong_messages(self):
        count = 0
        for filename in ("basic.json", "generated.json"):
            data = json.loads((Path(__file__).parent / "fixtures" / "bip322" / filename).read_text(encoding="utf-8"))
            for row in data["simple"]:
                supported = row["type"] in ("p2tr", "p2wpkh")
                for signature in row["bip322_signatures"]:
                    with self.subTest(kind=row["type"],message=row["message"]):
                        self.assertEqual(sig.verify(row["address"],row["message"],signature),supported)
                        self.assertFalse(sig.verify(row["address"],row["message"]+"tampered",signature))
                        self.assertFalse(sig.verify(row["address"],row["message"],signature+"AAAA"))
                        count += 1
            for row in data.get("error",[]):
                if "signature" in row:
                    self.assertFalse(sig.verify(row["address"],row["message"],row["signature"]),row.get("description"))
        self.assertGreaterEqual(count,10)

    def test_official_message_and_transaction_hashes(self):
        data=json.loads((Path(__file__).parent/"fixtures"/"bip322"/"basic.json").read_text(encoding="utf-8"))
        for row in data["tx_hashes"]:
            version,program=sig.address_program(row["address"])
            self.assertEqual(sig.tagged("BIP0322-signed-message",row["message"].encode()).hex(),row["message_hash"])
            self.assertEqual(sig.spend_txid(row["message"],bytes([version,len(program)])+program)[::-1].hex(),row["to_spend_tx_hash"])

    def test_ripemd160_fallback_matches_published_vectors(self):
        for message, expected in (
            (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
            (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
            (b"1234567890"*8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
        ):
            self.assertEqual(sig.ripemd160_python(message).hex(), expected)
        if not sig.HAVE_HASHLIB_RIPEMD160:
            self.skipTest("hashlib has no ripemd160 on this host")
        for length in (0,1,54,55,56,63,64,65,119,120,200):  # block-boundary padding
            blob = os.urandom(length)
            self.assertEqual(sig.ripemd160_python(blob), hashlib.new("ripemd160", blob).digest())

    def test_p2wpkh_verifies_where_hashlib_lacks_ripemd160(self):
        """A host without the OpenSSL legacy provider must still verify bc1q."""
        data = json.loads((Path(__file__).parent/"fixtures"/"bip322"/"generated.json").read_text(encoding="utf-8"))
        row = [item for item in data["simple"] if item["type"] == "p2wpkh"][0]
        signature = row["bip322_signatures"][0]
        with patch.object(sig, "HAVE_HASHLIB_RIPEMD160", False):
            self.assertTrue(sig.verify(row["address"], row["message"], signature))
            self.assertFalse(sig.verify(row["address"], row["message"]+"tampered", signature))

    def test_malformed_inputs_fail_closed(self):
        address="bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler"
        for value in (None,1,{},"", "x"*1000,"smpAAAA", "not-base64!"):
            self.assertFalse(sig.verify(address,"message",value))
        with self.assertRaises(ValueError): sig.address_program(address[:-1]+"q")

if __name__=="__main__":unittest.main()
