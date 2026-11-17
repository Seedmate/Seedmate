// Host test of signatures/lms_sign.html: runs the page's own crypto script.
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

const html = fs.readFileSync(path.join(__dirname, "../../signatures/lms_sign.html"), "utf8");
const core = html.match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const words = html.match(/const WORDLIST = "([a-z ]+)"/)[1].split(" ");
const ctx = { TextDecoder, Uint8Array, Int32Array, Math, Array, Object, Number };
vm.createContext(ctx);
vm.runInContext(core + `;Object.assign(globalThis, { sha256, toHex, fromHex, concat, bip39Entropy, deriveKey, deriveC,
  buildTree, publicKey, lmsSign, lmsVerify, hexProblem, otsPublic, PARAM_FIRMWARE,
  parseRecord, sigIndex, indexProblem, nextFreeIndex, recordHasIndex, recordRow, rowFields, folderName, crc32, zipStore });`, ctx);
const { sha256, toHex, fromHex, bip39Entropy, deriveKey, deriveC, buildTree, publicKey, lmsSign, lmsVerify, hexProblem, PARAM_FIRMWARE,
  parseRecord, sigIndex, indexProblem, nextFreeIndex, recordHasIndex, recordRow, rowFields, folderName, crc32, zipStore } = ctx;
const zlib = require("zlib");

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

  // The record of indexes (audit T1): an index that signed another file is refused
  const otherHex = new Uint8Array(Buffer.from(":020000040001F9\n:00000001FF\n"));
  const msg2 = sha256(otherHex);
  const recText = "# Firmware signatures\n\n```\n" + toHex(pub) + "\n```\n\n" +
    "| Index | Date | Version | Language | SHA-256 of UPDATE.HEX | Notes |\n|---|---|---|---|---|---|\n" +
    "| 0 | 2026-11-11 | v1 | English | " + toHex(msg2).toUpperCase() + " | |\n" +
    "| 7 | 2026-11-12 | v2 | English | " + toHex(msg).toUpperCase() + " | |\n" +
    "| 9 | 2026-11-13 | v3 | English | (hash forgotten) | |\n";
  const rec = parseRecord(recText);
  eq(rec.pub, pub, "public key read from the record");
  assert.deepStrictEqual(Array.from(rec.used, r => r.index), [0, 7, 9]);
  assert.strictEqual(rec.used[1].hash, toHex(msg));
  assert.strictEqual(rec.used[2].hash, null);
  assert.strictEqual(indexProblem(7, msg, rec, [], pub), null, "same file on its own index");
  assert(/INDEX 0 ALREADY SIGNED ANOTHER FILE/.test(indexProblem(0, msg, rec, [], pub)), "index of another file");
  assert(/INDEX 9/.test(indexProblem(9, msg, rec, [], pub)), "a row without a hash refuses its index");
  assert.strictEqual(indexProblem(10, msg, rec, [], pub), null, "a free index");
  assert(recordHasIndex(rec, 7, msg) && !recordHasIndex(rec, 10, msg));
  assert.strictEqual(nextFreeIndex(rec, []), 10);
  // Earlier signatures: one of this file passes, one of another file refuses its index
  const empty = parseRecord("```\n" + toHex(pub) + "\n```\n");
  assert.strictEqual(sigIndex(sig), 7);
  assert.strictEqual(sigIndex(sig.subarray(0, 100)), -1);
  assert.strictEqual(indexProblem(7, msg, empty, [{ name: "a.sig", bytes: sig }], pub), null, "re-signing the same file");
  const sigOther = lmsSign(key.id, key.seed, tree, PARAM_FIRMWARE, 7, deriveC(key.seed, 7, msg2), msg2);
  assert(/\(b\.sig\)/.test(indexProblem(7, msg, empty, [{ name: "b.sig", bytes: sigOther }], pub)), "signature of another file");
  assert.strictEqual(indexProblem(8, msg, empty, [{ name: "b.sig", bytes: sigOther }], pub), null, "another index is free");
  assert.strictEqual(nextFreeIndex(empty, [{ name: "b.sig", bytes: sigOther }]), 8);
  assert.strictEqual(recordRow(3, msg, "2026-11-17", "v2.0", false),
    "| 3 | 2026-11-17 | v2.0 | LANGUAGE | " + toHex(msg).toUpperCase() + " | |");
  const testRow = recordRow(3, msg, "2026-11-17", "v2.0b2", true);
  assert.deepStrictEqual(Object.assign({}, rowFields(testRow)), { date: "2026-11-17", version: "v2.0b2", test: true });
  assert.strictEqual(folderName(3, "2026-11-17", "v2.0b2", true).name, "003_2026-11-17_v2.0b2_test");
  assert.strictEqual(folderName(12, "2026-12-01", "v2.0", false).name, "012_2026-12-01_v2.0");
  assert(folderName(3, "2026-13-01", "v2.0", false).error, "month 13");
  assert(folderName(3, "17/11/2026", "v2.0", false).error, "date order");
  assert(folderName(3, "2026-11-17", "", false).error, "no version");
  assert(folderName(3, "2026-11-17", "v2.0/..", false).error, "no path in the version");
  test("signature folder names and record rows");

  // The zip of the folder, for browsers that cannot write one
  const big2 = new Uint8Array(crypto.randomBytes(5000));
  if (zlib.crc32) assert.strictEqual(crc32(big2), zlib.crc32(Buffer.from(big2)));
  assert.strictEqual(crc32(new Uint8Array(Buffer.from("123456789"))), 0xCBF43926);
  const zip = Buffer.from(zipStore([{ name: "003_x/UPDATE.HEX", bytes: hexBytes }, { name: "003_x/UPDATE.SIG", bytes: sig }]));
  let at = 0;
  for (const [name, bytes] of [["003_x/UPDATE.HEX", hexBytes], ["003_x/UPDATE.SIG", sig]]) {
    assert.strictEqual(zip.readUInt32LE(at), 0x04034b50);
    assert.strictEqual(zip.readUInt32LE(at + 14), crc32(bytes));
    assert.strictEqual(zip.readUInt32LE(at + 18), bytes.length);
    const n = zip.readUInt16LE(at + 26);
    assert.strictEqual(zip.toString("latin1", at + 30, at + 30 + n), name);
    assert(zip.subarray(at + 30 + n, at + 30 + n + bytes.length).equals(Buffer.from(bytes)));
    at += 30 + n + bytes.length;
  }
  const eocd = zip.length - 22;
  assert.strictEqual(zip.readUInt32LE(eocd), 0x06054b50);
  assert.strictEqual(zip.readUInt16LE(eocd + 10), 2);
  assert.strictEqual(zip.readUInt32LE(eocd + 16), at, "central directory right after the files");
  fs.writeFileSync(path.join(__dirname, "out.zip"), zip);
  test("zip of the folder");

  // The real record parses, with the key of the bootloader
  const realRec = parseRecord(fs.readFileSync(path.join(__dirname, "../../signatures/SIGNATURES.md"), "utf8"));
  const bootKey = fs.readFileSync(path.join(__dirname, "../../../bootloader/src/boot_lms.c"), "utf8")
    .match(/boot_lms_public_key\[[^\]]*\] = \{([^}]*)\}/)[1].match(/0x[0-9a-f]{2}/g).map(b => b.slice(2)).join("");
  assert.strictEqual(toHex(realRec.pub), bootKey, "SIGNATURES.md key = bootloader key");
  assert(realRec.used.length >= 1 && realRec.used.every(r => r.hash !== null), "every recorded index has its hash");
  test("index record: reuse refused, next free index, the real record");

  // signatures/: every row has its folder, and its files are those of the row
  const sigDir = path.join(__dirname, "../../signatures");
  for (const r of realRec.used) {
    const f = rowFields(r.line);
    const name = folderName(r.index, f.date, f.version, f.test).name;
    assert(name, "row " + r.index + " gives a folder name");
    const sigFile = path.join(sigDir, name, "UPDATE.SIG");
    assert(fs.existsSync(sigFile), "signatures/" + name + "/UPDATE.SIG is there");
    const s = new Uint8Array(fs.readFileSync(sigFile));
    assert.strictEqual(sigIndex(s), r.index, name + ": index of the signature");
    assert(lmsVerify(realRec.pub, fromHex(r.hash), s), name + ": the signature verifies for the hash of its row");
    const hexFile = path.join(sigDir, name, "UPDATE.HEX");
    if (fs.existsSync(hexFile)) {
      assert.strictEqual(crypto.createHash("sha256").update(fs.readFileSync(hexFile)).digest("hex"), r.hash, name + ": UPDATE.HEX of the row");
    }
  }
  for (const d of fs.readdirSync(sigDir, { withFileTypes: true })) {
    if (d.isDirectory()) assert(realRec.used.some(r => {
      const f = rowFields(r.line);
      return folderName(r.index, f.date, f.version, f.test).name === d.name;
    }), "signatures/" + d.name + " has its row in SIGNATURES.md");
  }
  test("signatures folder matches the record");

  // The page whose hash SIGNATURES.md publishes is this one (audit T3)
  const pageHash = crypto.createHash("sha256").update(fs.readFileSync(path.join(__dirname, "../../signatures/lms_sign.html"))).digest("hex");
  const listed = fs.readFileSync(path.join(__dirname, "../../signatures/SIGNATURES.md"), "utf8").match(/SHA-256 of lms_sign\.html[\s\S]*?\b([0-9A-Fa-f]{64})\b/);
  assert(listed, "SIGNATURES.md lists the hash of the page");
  assert.strictEqual(listed[1].toLowerCase(), pageHash, "the hash in SIGNATURES.md is of this page (update it with the page)");
  test("hash of the page in SIGNATURES.md");

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
