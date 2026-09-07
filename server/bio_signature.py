"""Verification-only BIP322-simple subset for native P2WPKH and P2TR key paths.

No signing, private keys, transaction broadcasting, script-path or multisig support.
Reject unsupported forms rather than treating them as verified. Python 3.6+.
Algorithms: BIP143/322/340/341/350; tested against bitcoin/bips public vectors.
The public-point arithmetic follows the BIP340 reference approach, used under
its CC0-1.0 code-license option; see docs/BIO_WALLET_SECURITY.md.
"""
import base64
import hashlib

P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

def sha(data):
    return hashlib.sha256(data).digest()

def sha2(data):
    return sha(sha(data))

def tagged(tag, data):
    h = sha(tag.encode("ascii"))
    return sha(h + h + data)

def _add(a, b):
    if a is None: return b
    if b is None: return a
    x, y = a
    u, v = b
    if x == u:
        if y != v or y == 0: return None
        slope = 3 * x * x * pow(2 * y, P - 2, P) % P
    else:
        slope = (v - y) * pow((u - x) % P, P - 2, P) % P
    nx = (slope * slope - x - u) % P
    return nx, (slope * (x - nx) - y) % P

def _mul(point, scalar):
    result = None
    while scalar:
        if scalar & 1: result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result

def _lift(x):
    if x >= P: raise ValueError("x")
    c = (x * x * x + 7) % P
    y = pow(c, (P + 1) // 4, P)
    if y * y % P != c: raise ValueError("point")
    return x, P - y if y & 1 else y

def address_program(address):
    if not isinstance(address, str) or len(address) > 90 or address.lower() != address:
        raise ValueError("address")
    if not address.startswith("bc1"): raise ValueError("native mainnet address required")
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    data = [alphabet.index(c) for c in address[3:]]
    if len(data) < 7: raise ValueError("checksum")
    chk = 1
    for v in [3, 3, 0, 2, 3] + data:  # HRP expand("bc")
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i, g in enumerate((0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3)):
            if (top >> i) & 1: chk ^= g
    version = data[0]
    if version not in (0, 1) or chk != (1 if version == 0 else 0x2bc830a3):
        raise ValueError("checksum")
    acc = bits = 0
    program = bytearray()
    for v in data[1:-6]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            program.append((acc >> bits) & 255)
    if bits >= 5 or (acc << (8 - bits)) & 255: raise ValueError("padding")
    if len(program) != (20 if version == 0 else 32): raise ValueError("unsupported address")
    return version, bytes(program)

def _witness(signature):
    if not isinstance(signature, str) or len(signature) > 300: raise ValueError("signature")
    if signature.startswith("smp"): signature = signature[3:]
    raw = base64.b64decode(signature, validate=True)
    if not raw or raw[0] not in (1, 2): raise ValueError("witness")
    offset, out = 1, []
    for _ in range(raw[0]):
        if offset >= len(raw): raise ValueError("truncated")
        length = raw[offset]
        offset += 1
        if length > 80 or offset + length > len(raw): raise ValueError("length")
        out.append(raw[offset:offset + length]); offset += length
    if offset != len(raw): raise ValueError("trailing")
    return out

def spend_txid(message, script):
    msg = b"\x00\x20" + tagged("BIP0322-signed-message", message.encode("utf-8"))
    tx = b"\x00"*4 + b"\x01" + b"\x00"*32 + b"\xff"*4 + bytes([len(msg)]) + msg + b"\x00"*4
    tx += b"\x01" + b"\x00"*8 + bytes([len(script)]) + script + b"\x00"*4
    return sha2(tx)

def _ecdsa(sig, pub, digest):
    if len(pub) != 33 or pub[0] not in (2, 3): return False
    point = _lift(int.from_bytes(pub[1:], "big"))
    if point[1] & 1 != pub[0] & 1: point = (point[0], P-point[1])
    if len(sig) < 8 or sig[0] != 48 or sig[1] != len(sig)-2 or sig[2] != 2: return False
    rlen = sig[3]
    if rlen == 0 or 4+rlen+2 > len(sig) or sig[4+rlen] != 2: return False
    slen = sig[5+rlen]
    rb, sb = sig[4:4+rlen], sig[6+rlen:]
    if slen != len(sb) or not slen: return False
    for part in (rb,sb):
        if part[0] & 128 or (len(part)>1 and part[0]==0 and not part[1]&128): return False
    r, s = int.from_bytes(rb,"big"), int.from_bytes(sb,"big")
    if not 0 < r < N or not 0 < s <= N//2: return False
    inv = pow(s,N-2,N)
    result = _add(_mul(G,int.from_bytes(digest,"big")*inv%N),_mul(point,r*inv%N))
    return result is not None and result[0]%N == r

def _schnorr(sig, pub, digest):
    r, s = int.from_bytes(sig[:32],"big"), int.from_bytes(sig[32:],"big")
    if r >= P or s >= N: return False
    point = _lift(int.from_bytes(pub,"big"))
    e = int.from_bytes(tagged("BIP0340/challenge",sig[:32]+pub+digest),"big")%N
    result = _add(_mul(G,s),_mul(point,N-e))
    return result is not None and not result[1]&1 and result[0] == r

def verify(address, message, signature):
    try:
        if not isinstance(message,str) or len(message.encode("utf-8")) > 4096: return False
        version, program = address_program(address)
        script = bytes([0 if version == 0 else 81,len(program)])+program
        stack = _witness(signature)
        outpoint = spend_txid(message,script)+b"\x00"*4
        output = b"\x00"*8+b"\x01\x6a"
        if version == 0:
            if len(stack) != 2: return False
            sig,pub = stack
            if not sig or sig[-1] != 1 or hashlib.new("ripemd160",sha(pub)).digest() != program: return False
            scriptcode = b"\x19\x76\xa9\x14"+program+b"\x88\xac"
            digest = sha2(b"\x00"*4+sha2(outpoint)+sha2(b"\x00"*4)+outpoint+scriptcode+b"\x00"*12+sha2(output)+b"\x00"*4+b"\x01\x00\x00\x00")
            return _ecdsa(sig[:-1],pub,digest)
        if len(stack) != 1: return False  # no annex or script-path claims
        sig = stack[0]
        if len(sig)==64: flag=0
        elif len(sig)==65 and sig[-1]==1: flag=1;sig=sig[:-1]
        else: return False
        digest = tagged("TapSighash",b"\x00"+bytes([flag])+b"\x00"*8+sha(outpoint)+sha(b"\x00"*8)+sha(bytes([len(script)])+script)+sha(b"\x00"*4)+sha(output)+b"\x00"*5)
        return _schnorr(sig,program,digest)
    except (ValueError,TypeError,IndexError,OverflowError):
        return False
