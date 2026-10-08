# Finding — Weak at-rest encryption of wallet seed phrase (MD5-derived key instead of scrypt)

**Target:** `crypto-com/chain-desktop-wallet` (Crypto.com Desktop Wallet), v1.5.1
**Component:** `src/crypto/Cryptographer.ts`, `src/service/storage/SecretStoreService.ts`, `src/service/WalletService.ts`
**Class:** CWE-916 — Use of password hash / key with insufficient computational effort
**Severity:** Medium (locally-exploitable; arguably High given the asset is a crypto wallet seed)
**CVSS 3.1:** `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` → 7.1
**Status:** Confirmed by code analysis + empirical reproduction with the app's exact crypto-js version (4.2.0).

> ⚠️ **Scope/eligibility caveat (read first):** In the Crypto.com HackerOne scope sheet, `chain-desktop-wallet` is marked `eligible_for_bounty: false`, `eligible_for_submission: false`, `max_severity: low`. So **this repo is almost certainly not a payout** and may be closed as out-of-scope. It is reported here because (a) it is a *real* security weakness worth responsibly disclosing, and (b) it is a strong **lead**: the same pattern (crypto-js passphrase-mode AES + scrypt-for-verification-only) should be checked in the **in-scope** products — the *Crypto.com Wallet Extension* and the mobile wallets — where a confirmed match **would** be in scope.

---

## Summary

The desktop wallet encrypts the mnemonic ("seed phrase") at rest with AES, intending to protect it with the memory-hard **scrypt** KDF. In practice the AES key is derived from the **raw user password** by `crypto-js` using OpenSSL's `EVP_BytesToKey` (**MD5, 1 iteration, 8-byte salt**), because the password is passed to `AES.encrypt()` as a **string** (passphrase mode). scrypt is only ever applied to a *separate password-verification hash* — never to the key that actually encrypts the seed.

Result: an attacker who obtains the on-disk encrypted seed store can mount an **offline brute-force against the user's password at MD5 speed** (orders of magnitude faster than the intended scrypt), recover the mnemonic, and steal all funds.

## Technical details

**1. The cipher is called with a string key (`src/crypto/Cryptographer.ts`):**
```ts
public async encrypt(data: string, key: string, iv: InitialVector) {
  const ivWordArray = lib.WordArray.create(iv.words, iv.sigBytes);
  const cipher = AES.encrypt(data, key, { mode: mode.CTR, padding: pad.Pkcs7, iv: ivWordArray }).toString();
  return { cipher, iv };
}
```
`key` is a **string**. In crypto-js, a string key is treated as a **passphrase**: it derives key+IV via `OpenSSLKdf` (`EvpKDF` = MD5, 1 iteration) with a random salt, and the explicitly-provided `iv` is **ignored**.

**2. The string key is the raw user password.** `WalletService.encryptWalletAndSetSession(key, wallet)` passes `key` straight into `cryptographer.encrypt(...)`, and every caller passes the plaintext password:
- `src/pages/create/create.tsx:1383` → `encryptWalletAndSetSession(password, wallet)`
- `src/pages/restore/restore.tsx:347`
- `src/pages/backup/backup.tsx:40`
- Decryption: `SecretStoreService.decryptPhrase(password, walletId)` → `cryptographer.decrypt(cipher, password, iv)` (e.g. `home.tsx:715`, `FormSend.tsx:147`, `WalletConnectModal.tsx:105`, …).

**3. scrypt is used only for verification, not for the key.** `SecretStoreService.checkIfPasswordIsValid()` and `signup.tsx` call `cryptographer.computeHash()` (scrypt) to store/compare a password hash — this never feeds the AES key.

**4. The scrypt parameters are also weak** (secondary): `Cryptographer.ts` uses `N=2048, r=8, p=1`. `N=2^11` is far below current guidance (OWASP ≥ `2^17` for interactive use). Even where scrypt *is* used (verification), it is under-parameterized.

## Proof of concept (library behavior, no live system touched)

Reproduced with `crypto-js@4.2.0` (the version in the app's `package.json`):
```js
const { AES, enc, lib, mode, pad } = require('crypto-js');
const iv = lib.WordArray.random(24);                       // app's generated 24-byte IV
const ct = AES.encrypt('mnemonic...', 'hunter2', { mode: mode.CTR, padding: pad.Pkcs7, iv }).toString();
Buffer.from(ct,'base64').slice(0,8).toString() === 'Salted__';   // => true  (OpenSSL passphrase/MD5 KDF in use)
AES.decrypt(ct, 'hunter2', { mode: mode.CTR, padding: pad.Pkcs7 }).toString(enc.Utf8) === 'mnemonic...'; // => true WITHOUT the IV
```
`Salted__` confirms OpenSSL passphrase mode (MD5 EVP_BytesToKey); successful decryption *without supplying the IV* confirms the app's IV is irrelevant and the key/IV come from the password via MD5.

## Impact

The entire point of encrypting the seed at rest is to resist an attacker who gets the files (infostealer malware — rampant against crypto users; cloud/Time-Machine backups of the app data dir; a shared or stolen machine; forensic recovery). A single MD5 round makes offline password cracking ~GPU-billions/sec, versus memory-hard scrypt which is the stated protection. For any password short of a long random one, seed recovery → full theft of all wallet funds becomes practical. The mnemonic is the root secret for every derived account.

## Remediation

1. **Derive the AES key with the memory-hard KDF and pass it as raw bytes**, not a passphrase string: feed the scrypt output (a `WordArray`/`Uint8Array`) as the key to `AES.encrypt`, with an explicit random IV, so crypto-js uses it directly and skips the MD5 passphrase KDF. (Or move to an AEAD such as libsodium `crypto_secretbox` / WebCrypto AES-GCM with an scrypt/Argon2id-derived key.)
2. **Raise scrypt parameters** to at least `N=2^17, r=8, p=1` (tune to ~100–250 ms on target hardware), and use them for the encryption key, not just verification.
3. Prefer an **authenticated** cipher (GCM) over CTR to also get integrity.
4. Transparently **re-encrypt existing wallets** on next unlock to migrate off the weak scheme.

## Suggested next step (for an in-scope, payable report)
Verify whether the **Crypto.com Wallet Extension** (in scope, max severity Medium) and/or the mobile wallets share this `crypto-js` passphrase-mode + scrypt-for-verification pattern. A confirmed match there is in scope and reportable on its own.
