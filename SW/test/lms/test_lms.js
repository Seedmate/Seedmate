// Host test of tools/lms_sign.html: runs the page's own crypto script.
//   node test_lms.js
// Checks SHA-256 against node's, the word list against the official hash, key
// generation and signing byte-exact against RFC 8554 Test Case 2, and writes a
// real H10 signature for verify_lms.py. Test words only ("abandon x11 about").
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const assert = require("assert");

const html = fs.readFileSync(path.join(__dirname, "../../tools/lms_sign.html"), "utf8");
const core = html.match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const words = html.match(/const WORDLIST = "([a-z ]+)"/)[1].split(" ");
const ctx = { TextDecoder, Uint8Array, Int32Array, Math, Array, Object, Number };
vm.createContext(ctx);
vm.runInContext(core + `;Object.assign(globalThis, { sha256, toHex, fromHex, concat, bip39Entropy, deriveKey, deriveC,
  buildTree, publicKey, lmsSign, lmsVerify, hexProblem, otsPublic, PARAM_FIRMWARE });`, ctx);
const { sha256, toHex, fromHex, bip39Entropy, deriveKey, deriveC, buildTree, publicKey, lmsSign, lmsVerify, hexProblem, PARAM_FIRMWARE } = ctx;

const eq = (a, b, what) => { assert.strictEqual(toHex(a), toHex(b), what); };
const test = (name) => console.log("  ok: " + name);

(async () => {
  // SHA-256 at every length around the block boundaries
  for (let n = 0; n < 300; n++) {
    const data = Uint8Array.from({ length: n }, (_, i) => (i * 7 + n) & 255);
    assert.strictEqual(toHex(sha256(data)), crypto.createHash("sha256").update(data).digest("hex"), "sha256 length " + n);
  }
  const big = crypto.randomBytes(700000);
  assert.strictEqual(toHex(sha256(new Uint8Array(big))), crypto.createHash("sha256").update(big).digest("hex"));
  test("SHA-256 against node");

  // The official english.txt, one word per line
  assert.strictEqual(words.length, 2048);
  assert.strictEqual(crypto.createHash("sha256").update(words.join("\n") + "\n").digest("hex"),
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");
  test("word list hash");

  // BIP39 words
  const abandon = "abandon ".repeat(11) + "about";
  eq(bip39Entropy(abandon, words).entropy, new Uint8Array(16), "abandon entropy");
  eq(bip39Entropy("abandon ".repeat(23) + "art", words).entropy, new Uint8Array(32), "24 words");
  assert(/CHECKSUM/.test(bip39Entropy("abandon ".repeat(12), words).error));
  assert(/WORD 2/.test(bip39Entropy("abandon xyz", words).error));
  assert(/12 OR 24/.test(bip39Entropy("abandon about", words).error));
  test("BIP39 validation");

  // RFC 8554 Test Case 2, second level tree: H5, W8, seed and C given
  const v = JSON.parse(fs.readFileSync(path.join(__dirname, "rfc_vector.json")));
  const rfcPub = fromHex(v.pub), rfcSig = fromHex(v.sig), rfcMsg = fromHex(v.message);
  const seed2 = fromHex("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
  const id2 = fromHex("215f83b7ccb9acbcd08db97b0d04dc2b");
  const par2 = { h: 5, w: 8 };
  const tree2 = await buildTree(id2, seed2, par2);
  eq(publicKey(id2, tree2, par2), rfcPub, "RFC public key from the seed");
  test("key generation equals the RFC (H5, W8)");
  const q = 4, C = rfcSig.subarray(8, 40);
  eq(lmsSign(id2, seed2, tree2, par2, q, C, rfcMsg), rfcSig, "RFC signature");
  test("signature equals the RFC byte by byte");
  assert(lmsVerify(rfcPub, rfcMsg, rfcSig));
  test("verifier accepts the RFC signature");

  // RFC top level tree: H10 like the firmware key, W4
  const seed1 = fromHex("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
  const id1 = fromHex("d08fabd4a2091ff0a8cb4ed834e74534");
  const tree1 = await buildTree(id1, seed1, { h: 10, w: 4 });
  assert.strictEqual(toHex(tree1.subarray(32, 64)), "32a58885cd9ba0431235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e");
  test("H10 root equals the RFC (W4)");

  // The firmware parameters, end to end
  const key = deriveKey(new Uint8Array(16));
  const t0 = Date.now();
  const tree = await buildTree(key.id, key.seed, PARAM_FIRMWARE);
  console.log("  tree of 1024 leaves: " + (Date.now() - t0) + " ms");
  const pub = publicKey(key.id, tree, PARAM_FIRMWARE);
  const hex = ":020000040000FA\n:00000001FF\n";
  const hexBytes = new Uint8Array(Buffer.from(hex));
  assert.strictEqual(hexProblem(hexBytes), null);
  const msg = sha256(hexBytes);
  const sig = lmsSign(key.id, key.seed, tree, PARAM_FIRMWARE, 7, deriveC(key.seed, 7, msg), msg);
  assert.strictEqual(sig.length, 1452);
  assert(lmsVerify(pub, msg, sig));
  eq(lmsSign(key.id, key.seed, tree, PARAM_FIRMWARE, 7, deriveC(key.seed, 7, msg), msg), sig, "same file, same index: same signature");
  test("firmware parameters: 1452 bytes, verifies, repeatable");

  // Every part of the signature matters; another file or key is refused
  for (const at of [0, 3, 4, 8, 39, 40, 500, 1127, 1128, 1132, 1451]) {
    const bad = sig.slice();
    bad[at] ^= 1;
    assert(!lmsVerify(pub, msg, bad), "changed byte " + at);
  }
  const other = sha256(new Uint8Array([1]));
  assert(!lmsVerify(pub, other, sig), "other file");
  const otherKey = deriveKey(new Uint8Array(16).fill(1));
  assert.notStrictEqual(toHex(otherKey.seed), toHex(key.seed));
  const badPub = pub.slice();
  badPub[30] ^= 1;
  assert(!lmsVerify(badPub, msg, sig), "other public key");
  assert(!lmsVerify(pub, msg, sig.subarray(0, 1451)), "short signature");
  test("changed signature, file and key are refused");

  // Files that are not firmware
  assert(hexProblem(new Uint8Array(Buffer.from("hello\n"))));
  assert(/END/.test(hexProblem(new Uint8Array(Buffer.from(":020000040000FA\n")))));
  assert(hexProblem(new Uint8Array(0)));
  test("non HEX files are refused");

  fs.writeFileSync(path.join(__dirname, "out_pub.txt"), toHex(pub) + "\n");
  fs.writeFileSync(path.join(__dirname, "out_fw.hex"), hexBytes);
  fs.writeFileSync(path.join(__dirname, "out.sig"), sig);
  console.log("All tests passed");
})().catch(e => { console.error("FAILED: " + e.message); process.exit(1); });
