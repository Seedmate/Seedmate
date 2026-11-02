# Seedmate vault - design (in progress, see section 12)

The vault keeps small secrets on the seed SD card (notes, logins, card data,
passphrases, multisig wallets), encrypted with a key that only the loaded seed
(with its passphrase) can derive. The device itself still stores nothing: the
card holds ciphertext, the key lives in RAM only while the vault is open.

Goals, in order: no extra RAM, simple to implement and to audit, recoverable
without a Seedmate (with the offline HTML backup tool), transparent to the
user (rule 4).

Out of scope for now: Krux / KEF compatibility, export and import of the whole
vault, animated QR. They can be added later without changing this format.

## 1. Where it lives on the SD card

Same raw card as the seeds (see the SD layout in `CLAUDE.md`):

| Sectors | Content |
|---|---|
| 0 | Legacy seed slot 1 (read only) |
| 1..199 | Seed slots 2..200 |
| 200..500 | Free, reserved |
| **501** | **Vault header** (plain) |
| **502..2046** | **Vault records**, one per sector (1545 sectors) |
| 2047 | Card marker (INITIALIZE CARD) |

The vault needs a valid card marker to write, like the seeds. It does not
depend on the SD WRITE setting (that one is only about seeds). INITIALIZE CARD
and WIPE ALL CARD destroy the vault (their warnings already say so).

ERASE SECTOR (SD CARD menu) is limited to the seed slots (sectors 0..199): today
it can zero any sector, which would break vault records, the header or the
marker behind the vault's back.

## 2. Key

```
vault_key = BIP85 HEX, 32 bytes, index 8377      (m/83696968'/128169'/32'/8377')
```

- Derived from the BIP32 root of the seed on screen, passphrase included: each
  passphrase has its own vault, and a vault can be recovered from the words
  and the passphrase alone, with any BIP85 tool.
- 8377 = "SM" (ASCII 83, 77): a fixed index nobody uses by chance for something else.
- The slow part is the seed (PBKDF2, 2048 rounds of HMAC-SHA512, seconds); the
  BIP85 step is a few HMACs. The BIP32 root is not kept today, so the vault key
  is derived **together with the wallet keys** in `bip84_derive_keys()` (the
  same PBKDF2 run, no second wait) and kept in a 32 byte static next to the key
  cache, bound to the same `bip84_seed_tag`. A new passphrase derives it again
  with the other keys; UNLOAD SEED and `transition_to_main()` wipe it. Opening
  the vault then costs only reading the card.

## 3. Cipher

**AES-256-GCM**, 12 byte nonce, 16 byte tag.

- Why not ChaCha20-Poly1305 (the first idea): the recovery tool is an HTML page,
  and browsers have AES-GCM built in (WebCrypto), not ChaCha. AES is already in
  the vendored trezor-crypto; it costs a few KB more flash than ChaCha.
- Nonce = `write_counter (8 bytes, big endian) || sector (4 bytes, big endian)`.
  `write_counter` is global to the vault (in the header) and goes up by one
  before every record write, so a nonce is never reused with the same key, not
  even after deleting and rewriting a sector. The camera-less device has no good
  random source; this needs none.
- Additional authenticated data = the 8 plain header bytes of the record
  (magic, version, sector, part): a record copied to another sector, or
  edited in its plain fields, fails the check.

## 4. Header sector (501, plain)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Magic `SMVAULT` + 0x00 |
| 8 | 1 | Format version = 1 |
| 9 | 7 | Reserved, 0 |
| 16 | 8 | `write_counter`, big endian |
| 24 | 8 | `vault_id`: random number written by INITIALIZE CARD, identifies the card |
| 32 | 194 | Occupancy bitmap: bit n (byte n/8, bit n%8, LSB first) = sector 502+n in use (1545 bits) |
| 226 | 282 | Reserved, 0 |
| 508 | 4 | CRC32 of bytes 0..507 (`ur_crc32_update`) |

- INITIALIZE CARD writes the header: magic, version, `vault_id`, the first
  `write_counter` and an empty bitmap. Hash = SHA-256(entropy pool, timers,
  "VAULT"), where the pool is the one the Shamir coefficients use (timer jitter
  of every key press, `update_entropy_coefficients()`, cleared afterwards since
  both values are public): `vault_id` = bytes 0..7, first counter = bytes 8..15
  shifted right by one (top bit clear, it never wraps).
- The first counter is random, not 0: two cards holding a vault of the same
  seed (a copy, a second card), or the same card initialized again, would
  otherwise start at the same counter and reuse nonces with the same key,
  which breaks AES-GCM (XOR of the texts, forged records).
- A card without a valid header (initialized by an older firmware, or damaged)
  is not written: "VAULT MAP DAMAGED, INITIALIZE THE CARD". Reading what can
  be read still works.
- The bitmap says which sectors are taken, not by whom: several vaults (other
  passphrases) can share a card without overwriting each other. It reveals how
  many sectors are used, nothing else.
- Write order for a new or edited entry: (1) the header with the counter
  advanced by the number of records (the nonces are recorded as used before
  any of them is written), (2) the records, each read back and decrypted,
  (3) the header with the new bits set and the old ones cleared, (4) the old
  records overwritten with zeros. A write that fails half way leaves the old
  entry and never a reused nonce, even if the vault is closed and opened again.
- `vault_id` is not secret. It only lets the device notice that the card in the
  slot is not the one the vault was opened from (see 5b): two cards that both
  have a vault have the same magic, but not the same random id.

## 5. Record sector (502..2046)

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | Magic `VR` |
| 2 | 1 | Version = 1 |
| 3 | 1 | Part: high nibble = part index (1..), low nibble = parts in the entry (1 or 2): 0x11 single, 0x12 / 0x22 two parts |
| 4 | 4 | Sector number, big endian (also in the AAD) |
| 8 | 12 | Nonce |
| 20 | 476 | Ciphertext |
| 496 | 16 | GCM tag |

Plaintext (476 bytes, always the full size, zero padded, so the length of the
content is hidden):

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | Type (see 6) |
| 1 | 1 | Title length (0..20) |
| 2 | 20 | Title, printable ASCII, zero padded |
| 22 | 2 | Body length, big endian |
| 24 | 452 | Body |

- Notes, logins and every template: body = text, up to 400 characters (the
  size of the text editor buffer; no buffer is enlarged). One sector.
- Descriptors: body = compact binary wallet (see 7). One or two sectors.
- A record that does not authenticate with this vault's key belongs to another
  seed or passphrase (or is damaged): it is skipped, and the list says how many
  there are ("3 ENTRIES OF OTHER KEYS").

## 5b. Finding the entries of the loaded seed, and robustness

No index (a single sector holding the list would be a single point of failure,
and each passphrase would need its own): each record stands alone.

Opening the vault:

1. Read the header (sector 501): magic, version, CRC.
2. For every sector marked in the bitmap (free sectors are not read): read it
   and try to decrypt it with the vault key.
   - Tag verifies: ours. Keep its sector and title in the list.
   - Tag fails: another seed or passphrase (or damaged). Skip it, count it.
3. Sort the list alphabetically (insertion sort, in place, no recursion).

Done once when the vault is opened; while it is open the list is in RAM and
only the entry being viewed, edited or deleted is read again.

Time per marked sector: reading 512 B (about 1-2 ms) and AES-GCM over 476 B in
software (about 3-6 ms), so about 0.1-0.2 s for 20 entries, 1.3-2 s for 255,
8-12 s for a full card shared by several passphrases. To be measured on the
device; progress bar "READING ENTRIES n OF m" meanwhile.

Possible later optimization, only if many entries of other passphrases make it
slow: a short keyed tag in clear per record (e.g. 4 bytes of HMAC(key, sector))
to skip other vaults' records without decrypting them. It depends on the
sector, so it does not link records of the same vault. Not in version 1; the
reserved bytes of the record header leave room for it.

Robustness:

- **Damaged map**: the SD controller handles physical sectors (wear leveling,
  bad block replacement, ECC); we only see logical sectors, so a damaged header
  is not a design case. If its CRC fails anyway, the vault refuses to write (it
  would otherwise think the card is empty and overwrite entries).
- **Card swapped**: the vault remembers `vault_id` and `write_counter` from the
  header it opened. Before every write (and every delete) it reads the marker
  and the header again; if the marker is gone, or the id or the counter differ,
  nothing is written: "CARD CHANGED, OPEN THE VAULT AGAIN".
- **Every write is read back and decrypted** before the header marks it and
  before an old version is freed; a failure says "SD WRITE ERROR" and keeps the
  old entry.
- Deleting is done only from the vault (its own entries), and the vault never
  touches the seed slots; ERASE SECTOR only touches the seed slots.

## 6. Entry types and templates

Every entry is a note: a title and a text. The type only says which template
it started from (the text is free once created) and how the device can use it.

| Type | Id | Created with | Template text |
|---|---|---|---|
| NOTE | 1 | Editor | (empty) |
| LOGIN | 2 | Editor | `SITE: ` / `USER: ` / `PASSWORD: ` |
| PASSPHRASE | 3 | Editor | (empty), title preset "PASSPHRASE"; its QR is the text only |
| CREDIT CARD | 4 | Editor | `NAME: ` / `NUMBER: ` / `EXPIRY: ` / `CVV: ` / `PIN: ` |
| EFF PASSWORD | 2 (LOGIN) | EFF dice generator | `PASSWORD: <generated>` |
| DESCRIPTOR | 16 | IMPORT DESCRIPTOR | Binary wallet, not editable |

- More templates later (WIFI, SSH, BANK ACCOUNT, SERVER...) are only a name and
  a text: no format change.
- PASSPHRASE is kept as a type: it starts as an empty note (no template, title
  preset "PASSPHRASE", editable), its QR holds only the text (never the title),
  and PASSPHRASE > FROM VAULT lists only these entries and loads the text
  (refused, with the reason, unless it is one printable line). Its warning: it
  is stored next to its seed, so it should live in the vault of the seed
  without passphrase.
- The text editor gets two new keys, made by splitting the RETURN key in three
  columns: RETURN (as today), **QR** and a **die** drawing:
  - **Die** (EFF): opens the EFF dice generator and inserts the result at the
    cursor.
  - **QR**: opens the QR READER; the text read is previewed in full with its
    length and inserted at the cursor only after OK (BACK discards it). Only
    printable ASCII is accepted, and it must fit in the 400 characters left;
    otherwise the reason is shown and nothing is inserted.

## 7. Descriptors without extra RAM

The loaded multisig wallet is already in RAM (`ms_wallet`). The vault stores a
binary copy of what is needed to rebuild it, never the descriptor text:

```
threshold (1) | key count (1) | flags: sorted (1) | account (4) |
per key: fingerprint (4) | chain code (32) | public key (33)      = 69 bytes each
```

- Up to 6 keys fit in one record; 7 keys take two records (parts 1/2 and 2/2),
  each encrypted and authenticated on its own.
- Saving and loading go one record at a time through the existing 512 byte
  sector buffer, straight from / into `ms_wallet`: no new buffer.
- Loading a DESCRIPTOR entry runs the same checks as IMPORT DESCRIPTOR
  (`descriptor_check_and_load()`: our key must be one of the cosigners, the
  account must match, review screen) before it becomes the active wallet.
- It is shown (policy, fingerprints, receive address 0) but not edited; to
  change it, import the new one and delete the old entry.
- Only available in multisig mode, from the wallet that is loaded: "SAVE TO VAULT"
  on the descriptor review screen.

## 8. RAM

Nothing new is allocated, but buffers are shared, so who uses what is fixed:

| Buffer | Size | Use while the vault is open |
|---|---|---|
| `buffer` (SD sector) | 512 B | SD reads and writes of one record (ciphertext); the text being edited while the editor is open (no SD I/O then); the text of a QR being shown |
| Fountain scratch | 8.7 KB | List: 255 x 24 B (sector 2, type 1, title 21) = 6.1 KB, bitmap copy 194 B; the last 512 B belong to the QR key of the editor |
| Vault key | 32 B static | From wallet load to UNLOAD SEED (see 2) |

- At most **255 entries** per vault (the list area).
- The QR insert key of the editor reads into the last 512 B of the fountain
  buffer (`editor_qr_read()`): `buffer` holds the text being edited and the
  start of the fountain buffer the list.
- Everything is wiped when leaving the vault.

Titles and texts are shown as typed (lower case allowed), as data, like the
EFF password; the screens' own texts stay upper case.

## 9. Screens

All of them with the button grid (rule 6), titles centered in light gray (rule 7).

**Opening** (wallet menu > VAULT): "VAULT xxxxxxxx" (master fingerprint of the
seed + passphrase in use), progress bar with the step ("DERIVING THE KEY",
"READING ENTRIES n OF m"), BACK cancels.

**List** (alphabetical by title):

```
        VAULT 73C5DA0A
 CREDIT CARD
 PROTON EMAIL
 STRIPE LOGIN
 WHATSAPP 2FA
 NEW ENTRY
 4 ENTRIES                [BACK][ ^ ][LOAD]
                          [DEL ][ v ][EDIT]
```

- UP / DOWN move (pages when there are more than fit), BACK leaves the vault.
- On an entry: OK = LOAD (view), LEFT = DEL, RIGHT = EDIT.
- On NEW ENTRY: OK = NEW; LEFT and RIGHT do nothing and are not shown.
- First time: "EMPTY VAULT" and only NEW ENTRY.
- Coming back from an entry, the cursor stays on it.

**New entry menu**: NOTE, LOGIN, PASSPHRASE, CREDIT CARD, EFF PASSWORD.
- Templates open the editor with the template text and the cursor on the title.
- EFF PASSWORD opens the EFF dice generator; at the end the editor opens with
  `PASSWORD: <generated>` as text and the cursor on the title.
- SAVE in the editor asks "SAVE TO VAULT? 'TITLE', 1 SECTOR" (BACK edits again).

**View** (LOAD): title and full text, UP / DOWN scroll, BACK returns to the
list, OK = QR of title and text together (the scanning side picks what it
needs), or of the text only for a PASSPHRASE entry; a text too long for one QR
says so ("TOO LONG FOR A QR"). The text is shown as is, passwords included.
The QR of an entry exists only here, in VIEW.

**Edit** (EDIT): the editor with the current title and text (with the EFF and
QR insert keys; no way to show the entry as a QR while editing); SAVE asks for
confirmation, writes the new version into free sectors and only then frees the
old ones (a write error never loses the entry).

**Delete** (DEL): red confirmation "DELETE 'TITLE'?" (BACK / DEL); the record is
overwritten with zeros and its bit cleared.

**Errors**, in plain words: "CARD NOT INITIALIZED", "SD READ ERROR",
"SD WRITE ERROR", "VAULT FULL" (no free sector or 255 entries), "ENTRY DAMAGED"
(fails authentication while it was expected to be ours), "TITLE NEEDED".

Plain text (note, title, key) is wiped from RAM after viewing or editing and
when leaving the vault.

## 10. Recovery without a Seedmate

Through the existing offline HTML backup page (the one that already recovers
Shamir backups), extended with a VAULT section:

1. Read the raw card into an image file (`dd` on Linux/macOS, Win32 Disk Imager
   on Windows). This breaks the "never put the seed card in a PC" rule, so it
   is documented as an emergency procedure only, on an offline computer.
2. In the HTML page: load the image, type the words and the passphrase.
3. The page derives the key (BIP39 PBKDF2-HMAC-SHA512 and BIP32 / BIP85
   hardened steps with WebCrypto HMAC and BigInt; no elliptic curve point
   needed) and decrypts every record with WebCrypto AES-GCM, showing titles and
   texts.

This document is the specification the page follows; any other tool can be
written from it.

## 11. Cost estimate

- Flash: AES + GCM from trezor-crypto, the vault screens and the format, around
  10-14 KB (today 169.4 KB of 238 KB used). Measured with step 7: about 16 KB
  (AES-GCM 6.5 KB, format 2 KB, screens 6 KB, the rest editor and EFF keys).
- RAM: none new (see 8).

## 12. Order of work

Each step builds, is tested and can be committed on its own; the firmware keeps
working between steps.

1. *(done)* **Protect the vault area**: ERASE SECTOR limited to the seed slots
   (sectors 0..199). Small, and needed before any vault data exists.
2. *(done, device timing still to measure)* **Vault key**: BIP85 HEX derivation (index 8377) sharing the steps of
   `bip85_derive_entropy()`, computed in `bip84_derive_keys()` with the wallet
   keys, cached and wiped with them. Host test with the BIP85 spec's HEX
   vector. Measure on the device how long the PBKDF2 and the BIP85 step take.
3. *(done: crypto and host tests; device timing when the screens use it.
   The Python reference is OpenSSL's AES-GCM, so no separate NIST vectors)*
   **AES-256-GCM**: link the trezor-crypto AES (smallest table option) and
   GCM, record encrypt / decrypt with nonce and AAD as in section 3. Host tests
   with NIST GCM vectors and byte-exact records against a Python reference
   (`test/vault/gen_vault.py`, also the reference for the HTML page). Measure
   on the device the time to read and decrypt one record; flash report.
4. *(done, host tested; reached by the screens of step 7)* **Format** (`vault.c`, no UI): header (magic, `vault_id`, counter, bitmap,
   CRC) written by INITIALIZE CARD *(done)*, free sector search, write and read-back
   check, delete, edit (new sector first, then free the old one), card swapped
   check (marker, `vault_id` and counter read again before every write),
   no write with a damaged header. Host test with a mock SD card: no nonce
   reused, a swapped card is refused.
5. *(done: `vault_scan()`, host tested)* **Listing**: scan the marked sectors, keep ours, count the others, sort
   alphabetically in the fountain buffer, 255 entries; host test.
6. *(done)* **Text editor keys**: the RETURN key split in three columns, RETURN, **QR**
   and a **die** (EFF). The die runs the EFF dice generator turned into a
   function that both TOOLS and the editor call; QR scans into the end of the fountain buffer,
   previews with the length, and OK inserts at the cursor (400 character
   limit, printable ASCII only). Useful already for the passphrase.
7. *(done; also a card initialized before the vault existed, whose header
   sector is blank, is offered "CREATE AN EMPTY VAULT" without touching
   anything else; the list counts other keys' records as "+n OTHERS")*
   **Vault screens, notes**: VAULT in the wallet menu, opening with progress
   and the fingerprint, "EMPTY VAULT", list (LOAD / DEL / EDIT / NEW, paging,
   cursor kept), view with scroll and QR (VIEW only), new entry menu with
   NOTE, LOGIN and CREDIT CARD templates, title of 20 characters, save and
   delete confirmations, every error of section 9 and 5b.
   Build and memory report.
8. *(done with step 7)* **EFF PASSWORD** in the new entry menu: generator, then the editor with
   `PASSWORD: <generated>` and the cursor on the title.
9. **PASSPHRASE** entries: empty note with the preset title, text-only QR
   *(these two done with step 7)*, PASSPHRASE > FROM VAULT lists them and loads the text.
10. **DESCRIPTOR** entries: SAVE TO VAULT on the descriptor review, one or two
    records through `buffer`, listed in both modes but loaded only in multisig
    ("SWITCH TO MULTI SIG"), always through `descriptor_check_and_load()`.
11. **Documentation and device tests**: `CLAUDE.md`; on real cards: timings,
    full vault, two passphrases on one card, card swapped with the vault open.
12. Later: the VAULT section of the offline HTML backup page, checked against
    `gen_vault.py`.
