// Runs the core script of tools/ur_psbt_animator.html and writes frames.txt:
// UR frames of the test PSBTs (all pure, mixed only, pure with losses) and QR
// matrices, which test_ur_anim.c checks against the firmware's own code.
// Usage: node gen_frames.js   (from test/ur_anim)
"use strict";
const fs = require("fs"), path = require("path"), vm = require("vm");
const html = fs.readFileSync(path.join(__dirname, "../../tools/ur_psbt_animator.html"), "utf8");
const core = html.match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const ctx = vm.createContext({});
vm.runInContext(core + ";Object.assign(globalThis,{sha256,crc32,urEncoder,qrEncode,qrSmallestVersion});", ctx);

// SHA-256 sanity against Node's
const crypto = require("crypto");
for (const n of [0, 3, 55, 56, 64, 119, 1000]) {
  const d = crypto.randomBytes(n);
  if (Buffer.from(ctx.sha256(new Uint8Array(d))).toString("hex") !== crypto.createHash("sha256").update(d).digest("hex"))
    throw new Error("sha256 mismatch at length " + n);
}

const dir = path.join(__dirname, "../psbt/sparrow");
const files = ["abandon send.psbt", "abandon send 3 inputs.psbt", "abandon big.psbt"];
const out = [];
let lcg = 12345;                                  // Fixed "random" losses, reproducible
const rnd = () => (lcg = (lcg * 1103515245 + 12345) % 2147483648) / 2147483648;

for (const f of files) {
  const psbt = new Uint8Array(fs.readFileSync(path.join(dir, f)));
  for (const frag of [60, 100, 150, 250]) {
    const enc = ctx.urEncoder(psbt, frag);
    if (enc.seqLen > 35 || enc.seqLen < 2) continue;      // Over the device limits, or not animated
    const n = enc.seqLen;
    const cases = {
      pure: Array.from({ length: n }, (_, i) => i + 1),
      mixed: Array.from({ length: 6 * n + 40 }, (_, i) => n + 1 + i),
      lossy: Array.from({ length: 8 * n + 40 }, (_, i) => i + 1).filter(() => rnd() >= 0.4),
    };
    for (const [name, seqs] of Object.entries(cases)) {
      out.push(`P ${f}\t${frag}\t${name}`);
      for (const s of seqs) out.push("F " + enc.part(s));
      out.push("END");
    }
  }
  // Single part UR (whole message in one fragment)
  const one = ctx.urEncoder(psbt, 100000);
  out.push(`S ${f}\t${one.part(1)}`);
}

// QR matrices: every ECC level, versions from small to large, all three modes
const texts = ["123456789012", "UR:CRYPTO-PSBT/1-3/LPADAXCF", "Hello, Seedmate! lower case = byte mode"];
const psbt = new Uint8Array(fs.readFileSync(path.join(dir, files[1])));
for (const frag of [20, 60, 100, 150, 250, 400]) texts.push(ctx.urEncoder(psbt, frag).part(2));
let qrCount = 0;
for (const t of texts) {
  for (let ecc = 0; ecc < 4; ecc++) {
    const v0 = ctx.qrSmallestVersion(t, ecc);
    if (!v0) continue;
    for (const v of [v0, Math.min(40, v0 + 1), Math.min(40, v0 + 7)]) {
      const q = ctx.qrEncode(t, v, ecc);
      let bits = "";
      for (const row of q.modules) bits += row.join("");
      const hex = bits.padEnd(Math.ceil(bits.length / 8) * 8, "0").match(/.{8}/g).map(b => parseInt(b, 2).toString(16).padStart(2, "0")).join("");
      out.push(`Q ${v} ${ecc} ${q.mask}\t${t}\t${hex}`);
      qrCount++;
    }
  }
}
fs.writeFileSync(path.join(__dirname, "frames.txt"), out.join("\n") + "\n");
console.log("frames.txt: " + out.filter(l => l[0] === "F").length + " frames, " + qrCount + " QR codes");
