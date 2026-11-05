#!/usr/bin/env python3
"""Independent check of what tools/lms_sign.html produces: an RFC 8554 verifier
written from the RFC, sharing nothing with the page. It also has to accept the
RFC's own Test Case 2 signature (rfc_vector.json, written by test_lms.js).

    python verify_lms.py <public key hex file> <firmware file> <signature file>
    python verify_lms.py --rfc rfc_vector.json
"""
import hashlib
import json
import struct
import sys

H = lambda *parts: hashlib.sha256(b"".join(parts)).digest()
LMS = {5: 5, 6: 10}                 # type code to height
OTS = {3: (4, 67, 4), 4: (8, 34, 0)}   # type code to w, p, ls


def coef(s, i, w):
    return ((1 << w) - 1) & (s[i * w // 8] >> (8 - (w * (i % (8 // w)) + w)))


def verify(pub, message, sig):
    lms_type, ots_type = struct.unpack(">II", pub[:8])
    identifier, root = pub[8:24], pub[24:]
    h = LMS[lms_type]
    w, p, ls = OTS[ots_type]
    if len(sig) != 4 + 4 + 32 + p * 32 + 4 + h * 32:
        return False
    q, sig_ots = struct.unpack(">II", sig[:8])
    if sig_ots != ots_type or q >= (1 << h):
        return False
    if struct.unpack(">I", sig[40 + p * 32:44 + p * 32])[0] != lms_type:
        return False
    c = sig[8:40]
    q_bytes = struct.pack(">I", q)

    digest = H(identifier, q_bytes, b"\x81\x81", c, message)
    total = sum((1 << w) - 1 - coef(digest, i, w) for i in range(256 // w))
    v = digest + struct.pack(">H", total << ls)

    ends = []
    for i in range(p):
        tmp = sig[40 + i * 32:72 + i * 32]
        for j in range(coef(v, i, w), (1 << w) - 1):
            tmp = H(identifier, q_bytes, struct.pack(">HB", i, j), tmp)
        ends.append(tmp)
    k = H(identifier, q_bytes, b"\x80\x80", *ends)

    node = (1 << h) + q
    tmp = H(identifier, struct.pack(">I", node), b"\x82\x82", k)
    offset = 44 + p * 32
    while node > 1:
        sibling = sig[offset:offset + 32]
        offset += 32
        left, right = (sibling, tmp) if node & 1 else (tmp, sibling)
        node >>= 1
        tmp = H(identifier, struct.pack(">I", node), b"\x83\x83", left, right)
    return tmp == root


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--rfc":
        vector = json.load(open(sys.argv[2]))
        pub, message, sig = (bytes.fromhex(vector[k]) for k in ("pub", "message", "sig"))
        assert verify(pub, message, sig), "the RFC signature must verify"
        bad = bytearray(sig)
        bad[100] ^= 1
        assert not verify(pub, message, bytes(bad)), "a changed signature must not verify"
        print("RFC vector: ok")
        return
    pub = bytes.fromhex(open(sys.argv[1]).read().strip())
    message = hashlib.sha256(open(sys.argv[2], "rb").read()).digest()
    sig = open(sys.argv[3], "rb").read()
    ok = verify(pub, message, sig)
    print("signature index", struct.unpack(">I", sig[:4])[0], "VERIFIED" if ok else "BAD")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
