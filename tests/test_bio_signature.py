import json
import unittest
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

    def test_malformed_inputs_fail_closed(self):
        address="bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler"
        for value in (None,1,{},"", "x"*1000,"smpAAAA", "not-base64!"):
            self.assertFalse(sig.verify(address,"message",value))
        with self.assertRaises(ValueError): sig.address_program(address[:-1]+"q")

if __name__=="__main__":unittest.main()
