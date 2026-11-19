// Test vectors for users who build their own recovery tool (the "Build your own"
// tab of the backup tool page). They come from backup_vectors.json, which the
// firmware's own code computed (gen_backup_vectors.exe); only the conversion to
// words is done here, with Node's SHA-256 and the official word list.
//
//   node gen_user_vectors.js [page folder]          writes them
//   node gen_user_vectors.js [page folder] --check  fails if the page or the files differ
//
// The page folder defaults to the clone beside the firmware repository
// (../../../../HTMLbackup). It writes the vectors into the page
// (<script type="application/json" id="byo-vectors">) and, with the prompt and
// the specification of the page, into build-your-own/ of the page's repository.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const args = process.argv.slice(2);
const check = args.includes('--check');
const dir = args.find(a => a !== '--check') || path.join(__dirname, '../../../../HTMLbackup');
const pagePath = path.join(dir, 'index.html');
// Line ends as stored in git (a Windows checkout may have CRLF)
const lf = t => t.replace(/\r\n/g, '\n');
let html = lf(fs.readFileSync(pagePath, 'utf8'));
const V = JSON.parse(fs.readFileSync(path.join(__dirname, 'backup_vectors.json'), 'utf8'));

function block(id) {
    const re = new RegExp('(<script type="[^"]+" id="' + id + '">\\n)([\\s\\S]*?)(\\n</script>)');
    const m = re.exec(html);
    if (!m) throw new Error('no block ' + id + ' in ' + pagePath);
    return { re, text: m[2] };
}

// ---- words, independently of the page's code
const words = JSON.parse(/var WORDS = (\[[^\]]*\]);/.exec(html)[1]);
const listHash = crypto.createHash('sha256').update(words.join('\n') + '\n').digest('hex');
if (listHash !== '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda') throw new Error('word list');
const sha = b => crypto.createHash('sha256').update(b).digest();
function mnemonic(hex) {
    const e = Buffer.from(hex, 'hex');
    let bits = '';
    for (const b of e) bits += b.toString(2).padStart(8, '0');
    const h = sha(e);
    let hb = '';
    for (const b of h) hb += b.toString(2).padStart(8, '0');
    bits += hb.slice(0, e.length / 4);
    const out = [];
    for (let i = 0; i < bits.length; i += 11) out.push(words[parseInt(bits.slice(i, i + 11), 2)]);
    return out.join(' ');
}
const RANKS = 'A23456789TJQK', SUITS = 'CDHS';
const cardName = c => RANKS[c % 13] + SUITS[Math.floor(c / 13)];

// The seeds of gen_backup_vectors.c: 0..7 fixed patterns, 8.. pseudo random test data
const seeds = [];
for (const v of V.cards) seeds.push(v.in);
const r12 = seeds[8], r24 = seeds[9], r12b = seeds[10], r24b = seeds[11];

const out = {
    about: 'Seedmate test vectors, version 1. Public test seeds with no funds. Computed with the Seedmate firmware\'s own code ' +
           '(firmware repository, test/backup). Every mnemonic is BIP39 English. See the specification for the formats.',
    bip39: ['00000000000000000000000000000000', '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f', r12, r24]
        .map(e => ({ entropy: e, mnemonic: mnemonic(e) })),
    coins: [r12].map(e => ({
        tosses: Buffer.from(e, 'hex').reduce((s, b) => s + b.toString(2).padStart(8, '0'), ''),
        note: '0 is heads, 1 is tails', mnemonic: mnemonic(e) })),
    dice: V.dice.slice(0, 2).map(v => ({ rolls: v.rolls, words: v.bytes === 16 ? 12 : 24, mnemonic: mnemonic(v.out) })),
    dice_hash: V.dicehash.filter(v => v.rolls.length === 50 || v.rolls.length === 99)
        .map(v => ({ rolls: v.rolls, mode: v.keystone ? '0-5' : '1-6', words: v.bytes === 16 ? 12 : 24, mnemonic: mnemonic(v.out) })),
    poker_cards: V.poker.slice(0, 2).map(v => ({ cards: v.cards.map(cardName).join(' '), words: v.bytes === 16 ? 12 : 24, mnemonic: mnemonic(v.out) })),
    obfuscation: [],
    xor: [],
    shamir: [],
    cards: [seeds[2], r12, r24, r12b].map(e => {
        const v = V.cards.find(x => x.in === e);
        return { mnemonic: mnemonic(e), decks: v.decks, cards: v.seq.map(cardName).join(' ') };
    })
};

// Obfuscation: a few values of each method on two seeds
const picks = [['not'], ['swap'], ['shift', 'left', 5], ['shift', 'right', 11], ['shift', 'left', 200],
               ['addsub', 'add', 1024], ['addsub', 'sub', 3000], ['addsub', 'add', 7], ['wordxor', 1234], ['wordxor', 3]];
for (const seed of [r12, r24]) {
    for (const p of picks) {
        const v = V.obfuscation.find(x => x.in === seed && x.op === p[0] &&
            (p[0] === 'wordxor' ? x.word === p[1] : p.length === 1 || (x.dir === p[1] && x.n === p[2])));
        if (!v) throw new Error('missing obfuscation ' + p.join(' '));
        const item = { mnemonic: mnemonic(seed) };
        if (v.op === 'not') item.method = 'not';
        else if (v.op === 'swap') item.method = 'byte_swap';
        else if (v.op === 'shift') { item.method = 'shift_' + v.dir; item.bits = v.n; }
        else if (v.op === 'addsub') { item.method = v.dir; item.value = v.n; }
        else { item.method = 'word_xor'; item.word = words[v.word]; item.word_index = v.word; }
        item.result = mnemonic(v.out);
        out.obfuscation.push(item);
    }
}

// XOR: byte by byte (the firmware's multi_input_store() does the same)
const xorHex = list => {
    const r = Buffer.from(list[0], 'hex');
    for (const x of list.slice(1)) Buffer.from(x, 'hex').forEach((b, i) => { r[i] ^= b; });
    return r.toString('hex');
};
for (const list of [[r12, r12b], [r24, r24b, seeds[7]], [r12, r12b, seeds[2], seeds[4]]]) {
    out.xor.push({ inputs: list.map(mnemonic), result: mnemonic(xorHex(list)) });
}

// Shamir: whole splits of the firmware, with their coefficients
for (const [k, n, seed] of [[2, 3, seeds[12]], [3, 5, seeds[9]], [6, 9, seeds[18]], [5, 9, seeds[15]]]) {
    const v = V.shamir.find(x => x.k === k && x.n === n && x.secret === seed);
    if (!v) throw new Error('missing Shamir ' + k + ' of ' + n);
    out.shamir.push({ secret: mnemonic(v.secret), k, n,
        coefficients_hex: v.coeffs, note: 'coefficient arrays c1..c(k-1); the device makes them random',
        shares: v.shares.map((s, i) => ({ id: i + 1, mnemonic: mnemonic(s) })) });
}

const json = JSON.stringify(out, null, 2);
const prompt = block('byo-prompt').text, spec = block('byo-spec').text;
const files = {
    'seedmate_test_vectors.json': json + '\n',
    'PROMPT.md': prompt + '\n',
    'SPECIFICATION.md': spec + '\n',
};
const vb = block('byo-vectors');
const newHtml = html.replace(vb.re, (m, a, b, c) => a + json + c);
const fdir = path.join(dir, 'build-your-own');
if (check) {
    let bad = 0;
    if (newHtml !== html) { console.log('the vectors in the page are not the current ones'); bad++; }
    for (const [f, t] of Object.entries(files)) {
        const p = path.join(fdir, f);
        if (!fs.existsSync(p) || lf(fs.readFileSync(p, 'utf8')) !== t) { console.log(f + ' is not current'); bad++; }
    }
    if (bad) { console.log('run: node gen_user_vectors.js'); process.exit(1); }
    console.log('user vectors current');
} else {
    fs.writeFileSync(pagePath, newHtml);
    fs.mkdirSync(fdir, { recursive: true });
    for (const [f, t] of Object.entries(files)) fs.writeFileSync(path.join(fdir, f), t);
    console.log('wrote the user vectors (' + json.length + ' characters)');
}
