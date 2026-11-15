// Runs bbqrFrames() of tools/ur_psbt_animator.html (its core script) on the
// abandon test files and writes anim_frames.txt, which test_bbqr.c decodes
// with the firmware's bbqr.c. Z is compressed with Node's raw deflate (32 KB
// window, as the browser's CompressionStream("deflate-raw") that the page uses).
// Usage: node anim_frames.js   (from test/bbqr)
"use strict";
const fs = require("fs"), path = require("path"), vm = require("vm"), zlib = require("zlib");
const html = fs.readFileSync(path.join(__dirname, "../../tools/ur_psbt_animator.html"), "utf8");
const core = html.match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const ctx = vm.createContext({});
vm.runInContext(core + ";Object.assign(globalThis,{bbqrFrames});", ctx);

const files = [["P", "abandon taproot.psbt"], ["P", "abandon nested multisig.psbt"], ["U", "MSDESC.TXT"], ["U", "MSCOLD.TXT"]];
const out = [];
let series = 0;
for (const [type, name] of files) {
  const data = new Uint8Array(fs.readFileSync(path.join(__dirname, "../psbt", name)));
  for (const enc of ["H", "2", "Z"]) {
    const sent = enc === "Z" ? new Uint8Array(zlib.deflateRawSync(data, { level: 9 })) : data;
    for (const chars of [224, 758]) {          // Sparrow low and medium density
      const frames = ctx.bbqrFrames(sent, enc, type, chars);
      out.push("FILE ../psbt/" + name + "|" + type + "|" + frames.length);
      for (const f of frames) {
        if (f.length > chars) throw new Error("frame over " + chars + " characters");
        out.push(f);
      }
      series++;
    }
  }
}
fs.writeFileSync(path.join(__dirname, "anim_frames.txt"), out.join("\n") + "\n");
console.log("wrote anim_frames.txt,", series, "series");
