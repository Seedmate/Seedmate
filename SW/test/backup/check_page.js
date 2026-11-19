// Runs the core script of the backup HTML page (Seedmate_HTML_backup,
// <script id="seedmate-core">, no DOM) against what the firmware computes
// (backup_vectors.json from gen_backup_vectors.exe), plus BIP39 / SHA-256
// references and the page's own round trips.
//
//   node check_page.js [index.html] [shamir vectors .txt]
//
// The page defaults to the clone next to the firmware repository,
// C:\Seedmate\HTMLbackup\index.html (../../../../HTMLbackup from here).
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const pagePath = process.argv[2] || path.join(__dirname, '../../../../HTMLbackup/index.html');
const html = fs.readFileSync(pagePath, 'utf8');
function script(id) {
    const m = new RegExp('<script id="' + id + '">([\\s\\S]*?)</script>').exec(html);
    if (!m) throw new Error('no <script id="' + id + '"> in ' + pagePath);
    return m[1];
}
const ctx = {};
vm.createContext(ctx);
vm.runInContext(script('qrcode') + '\n' + script('seedmate-core') + '\nthis.SM = SM; this.QRCode = QRCode;', ctx);
const SM = ctx.SM, QR = ctx.QRCode;
const V = JSON.parse(fs.readFileSync(path.join(__dirname, 'backup_vectors.json'), 'utf8'));

let fails = 0, checks = 0;
function eq(got, want, what) {
    checks++;
    if (got !== want) {
        fails++;
        if (fails <= 20) console.log('FAIL ' + what + '\n  got  ' + got + '\n  want ' + want);
    }
}
const hex = SM.toHex, unhex = SM.fromHex;

// ---- the word list is the official one, and SHA-256 matches Node's
eq(crypto.createHash('sha256').update(SM.WORDS.join('\n') + '\n').digest('hex'),
   '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda', 'BIP39 English list');
for (let n = 0; n < 300; n++) {
    const b = crypto.randomBytes(n);
    eq(hex(SM.sha256(b)), crypto.createHash('sha256').update(b).digest('hex'), 'sha256 of ' + n + ' bytes');
}

// ---- BIP39 reference vectors (trezor/python-mnemonic)
const BIP39 = [
    ['00000000000000000000000000000000', 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'],
    ['7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f', 'legal winner thank year wave sausage worth useful legal winner thank yellow'],
    ['80808080808080808080808080808080', 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above'],
    ['ffffffffffffffffffffffffffffffff', 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'],
    ['0000000000000000000000000000000000000000000000000000000000000000', 'abandon '.repeat(23) + 'art'],
    ['7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f', 'legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title'],
    ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'zoo '.repeat(23) + 'vote'],
    ['9e885d952ad362caeb4efe34a8e91bd2', 'ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic'],
    ['68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c', 'hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length'],
];
for (const [e, words] of BIP39) {
    eq(SM.mnemonic(unhex(e)).words.join(' '), words, 'mnemonic of ' + e);
    const p = SM.parseMnemonic(words, true);
    eq(p.error ? p.error : hex(p.entropy), e, 'parse ' + words.slice(0, 20));
    const four = words.split(' ').map(w => w.slice(0, 4)).join(' ');
    const q = SM.parseMnemonic(four, true);
    eq(q.error ? q.error : hex(q.entropy), e, 'parse 4 letter prefixes');
}
eq(!!SM.parseMnemonic('abandon '.repeat(12).trim(), true).error, true, 'wrong checksum refused');
eq(hex(SM.parseMnemonic('abandon '.repeat(12).trim(), false).entropy), '0'.repeat(32), 'checksum computed again');

// ---- obfuscation
const inverse = { left: 'right', right: 'left', add: 'sub', sub: 'add' };
for (const v of V.obfuscation) {
    const e = unhex(v.in);
    let got, back;
    if (v.op === 'not') { got = SM.obfNot(e); back = SM.obfNot(got); }
    else if (v.op === 'swap') { got = SM.obfSwap(e); back = SM.obfSwap(got); }
    else if (v.op === 'shift') { got = SM.obfShift(e, v.n, v.dir === 'right'); back = SM.obfShift(got, v.n, v.dir !== 'right'); }
    else if (v.op === 'addsub') { got = SM.obfAddSub(e, v.n, v.dir === 'sub'); back = SM.obfAddSub(got, v.n, inverse[v.dir] === 'sub'); }
    else if (v.op === 'wordxor') { got = SM.obfWordXor(e, v.word); back = SM.obfWordXor(got, v.word); }
    const what = v.op + (v.dir ? ' ' + v.dir : '') + (v.n !== undefined ? ' ' + v.n : '') + (v.word !== undefined ? ' ' + v.word : '') + ' of ' + v.in;
    eq(hex(got), v.out, what);
    eq(hex(back), v.in, 'undo ' + what);
}

// ---- cards: the same order as MNEMONIC TO CARDS, and back
for (const v of V.cards) {
    const e = SM.cardsEncode(unhex(v.in));
    eq(e.seq.join(','), v.seq.join(','), 'card order of ' + v.in);
    eq(e.decks, v.decks, 'decks of ' + v.in);
    const names = v.seq.map(SM.cardName).join(' ');
    const p = SM.parseCards(names);
    eq(p.error || p.cards.join(','), v.seq.join(','), 'card names read back');
    const d = SM.cardsDecode(v.seq);
    eq(d.error || hex(d.entropy), v.in, 'cards back to ' + v.in);
}
eq(SM.parseCards('10h th T♥ a♠').cards.join(','), '35,35,35,39', 'card spellings');
eq(!!SM.parseCards('10h 1h').error, true, 'not a card refused');

// ---- POKER CARDS, raw dice, STRING HASH
for (const v of V.poker) {
    const r = SM.pokerEntropy(v.cards, v.bytes);
    eq(r.error || hex(r.entropy), v.out, 'poker cards ' + v.cards.length);
    eq(!!SM.pokerEntropy(v.cards.concat([0]), v.bytes).error, true, 'one card too many refused');
    eq(!!SM.pokerEntropy(v.cards.slice(0, -1), v.bytes).error, true, 'one card short refused');
}
for (const v of V.dice) {
    const r = SM.diceEntropy(v.rolls, v.bytes);
    eq(r.error || hex(r.entropy), v.out, 'dice ' + v.rolls.length + ' rolls');
    eq(!!SM.diceEntropy(v.rolls + '1', v.bytes).error, true, 'one roll too many refused');
}
for (const v of V.dicehash) {
    eq(hex(SM.diceHash(v.rolls, v.keystone, v.bytes)), v.out, 'dice hash ' + v.rolls.length + (v.keystone ? ' keystone' : ''));
}

// ---- Shamir: the same shares as the firmware for the same coefficients, and
// every subset of k shares gives the secret back
function subsets(n, k) {
    const out = [], cur = [];
    (function rec(s) {
        if (cur.length === k) { out.push(cur.slice()); return; }
        for (let i = s; i <= n; i++) { cur.push(i); rec(i + 1); cur.pop(); }
    })(1);
    return out;
}
for (const v of V.shamir) {
    const shares = SM.sssSplit(unhex(v.secret), v.k, v.n, v.coeffs.map(unhex));
    eq(shares.map(hex).join(','), v.shares.join(','), 'Shamir ' + v.k + ' of ' + v.n + ' of ' + v.secret);
    for (const s of subsets(v.n, v.k)) {
        const r = SM.sssCombine(s.map(x => ({ x: x, y: unhex(v.shares[x - 1]) })));
        eq(hex(r), v.secret, 'merge of shares ' + s.join(','));
    }
}

// ---- optional: shares written down from the earlier page (a text file of
// "Origin mnemonic" and "Share ID: n" lines); every subset of k gives the origin
function checkShareFile(file) {
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).map(l => l.trim());
    let origin = null, k = 0, shares = [], runs = 0;
    const finish = () => {
        if (!origin || !shares.length) return;
        runs++;
        for (const s of subsets(shares.length, k)) {
            const r = SM.sssCombine(s.map(i => ({ x: shares[i - 1].x, y: shares[i - 1].y })));
            eq(SM.mnemonic(r).words.join(' '), origin, 'share file, merge of ' + s.join(','));
        }
        shares = [];
    };
    for (let i = 0; i < lines.length; i++) {
        let m;
        if (/^(origin|master) mnemonic/i.test(lines[i])) {
            finish();
            const words = lines[i + 1];
            origin = SM.mnemonic(SM.parseMnemonic(words, true).entropy).words.join(' ');
        } else if ((m = /^Split k=(\d+) n=(\d+)/.exec(lines[i]))) {
            finish();
            k = +m[1];
        } else if ((m = /^Share ID: (\d+)/.exec(lines[i]))) {
            let j = i + 1;
            while (!/^[a-z]+( [a-z]+){11,}$/.test(lines[j])) j++;
            const p = SM.parseMnemonic(lines[j], true);
            eq(!!p.error, false, 'share file, share ' + m[1] + ' is a valid mnemonic');
            shares.push({ x: +m[1], y: p.entropy });
        }
    }
    finish();
    console.log('share file: ' + runs + ' splits checked');
}
if (process.argv[3]) checkShareFile(process.argv[3]);

// ---- the SeedQR and Compact SeedQR fit the versions the device uses
for (const v of V.cards) {
    const e = unhex(v.in), small = e.length === 16;
    const std = SM.mnemonic(e).indexes.map(i => ('000' + i).slice(-4)).join('');
    const m1 = new QR.Model(small ? 2 : 3, small ? QR.Level.Q : QR.Level.M);
    m1.addData(std, 'auto'); m1.make();
    eq(m1.getModuleCount(), small ? 25 : 29, 'SeedQR size');
    const m2 = new QR.Model(small ? 1 : 2, QR.Level.L);
    m2.addData(Array.from(e, b => String.fromCharCode(b)).join(''), 'byte'); m2.make();
    eq(m2.getModuleCount(), small ? 21 : 25, 'Compact SeedQR size');
}

console.log(checks + ' checks, ' + fails + ' failed');
process.exit(fails ? 1 : 0);
