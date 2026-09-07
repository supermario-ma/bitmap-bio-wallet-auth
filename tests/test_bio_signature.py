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

    def test_scalar_multiplication_matches_published_secp256k1_points(self):
        multiples = {
            2: (0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,
                0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a),
            3: (0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,
                0x388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672),
            4: (0xe493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13,
                0x51ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922),
        }
        for scalar, expected in multiples.items():
            self.assertEqual(sig._affine(sig._mul(sig.G, scalar)), expected)
        self.assertEqual(sig._affine(sig._mul(sig.G, 1)), sig.G)
        # (N-1)G is -G, and NG is the point at infinity.
        self.assertEqual(sig._affine(sig._mul(sig.G, sig.N-1)), (sig.G[0], sig.P-sig.G[1]))
        self.assertIsNone(sig._affine(sig._mul(sig.G, sig.N)))
        self.assertIsNone(sig._affine(sig._mul(sig.G, 0)))

    def test_point_addition_handles_doubling_and_infinity(self):
        g = (sig.G[0], sig.G[1], 1)
        two = sig._affine(sig._jadd(g, g))
        self.assertEqual(two, sig._affine(sig._mul(sig.G, 2)))
        negative = (sig.G[0], sig.P-sig.G[1], 1)
        self.assertIsNone(sig._affine(sig._jadd(g, negative)))  # G + (-G)
        self.assertEqual(sig._affine(sig._jadd(g, (0,0,0))), sig.G)  # identity element
        self.assertEqual(sig._affine(sig._jadd((0,0,0), g)), sig.G)

    def test_malformed_inputs_fail_closed(self):
        address="bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler"
        for value in (None,1,{},"", "x"*1000,"smpAAAA", "not-base64!"):
            self.assertFalse(sig.verify(address,"message",value))
        with self.assertRaises(ValueError): sig.address_program(address[:-1]+"q")

if __name__=="__main__":unittest.main()
