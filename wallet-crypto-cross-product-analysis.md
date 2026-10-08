# Cross-product check — does the weak seed-encryption pattern exist "everywhere"?

**Question:** The Crypto.com *Desktop Wallet* derives its seed-encryption key with crypto-js passphrase mode (MD5, 1 iteration) instead of a memory-hard KDF (see `finding-wallet-seed-encryption.md`). Does the same weakness appear in the other Crypto.com wallet products?

**Short answer: No.** The flaw is isolated to the older desktop wallet. The modern browser extension uses a proper KDF + authenticated cipher. Mapping to bounty eligibility, none of the affected/analyzed assets are bounty-eligible, and the eligible main mobile app is a separate modern codebase that (on the extension evidence) is unlikely to share the old pattern.

---

## What was analyzed (static analysis of public code only)

### 1. Desktop Wallet — `crypto-com/chain-desktop-wallet` v1.5.1  → **VULNERABLE** (Medium)
- Seed encrypted via `crypto-js` `AES.encrypt(mnemonic, <rawPassword string>, …)` → OpenSSL passphrase KDF = **MD5, 1 iteration**; scrypt used only for the password-verification hash.
- Details + PoC: `finding-wallet-seed-encryption.md`.
- **Bounty status: NOT eligible** (`eligible_for_bounty=false`, `max_severity=low` in scope).

### 2. Onchain / Wallet Extension — `hifafgmccdpekplomjjkcfgodnhcellj` v3.10.4  → **NOT vulnerable to this flaw**
Analyzed the publicly-distributed CRX (unpacked, static). The seed vault is encrypted with **`browser-passworder`** (MetaMask's encryptor):
- `keyFromPassword()` → WebCrypto `crypto.subtle.deriveKey({ name:"PBKDF2", salt, iterations: 1e4, hash:"SHA-256" }, …)`
- `encryptWithKey()` → **AES-GCM** (authenticated encryption).
- Crypto primitives are `@noble/hashes` (pbkdf2, scrypt, sha2) and libsodium (argon2id available); `crypto-js` is bundled but **not** used for the vault (no OpenSSL `Salted__` passphrase ciphertext anywhere).
- The `pbkdf2(phrase, "mnemonic"+pass, 2048, 64, "sha512")` present in the bundle is the **BIP-39 standard seed derivation**, not vault encryption — correct per spec.

So the desktop wallet's MD5-single-round flaw is **absent** here.

- **Minor hardening note (LOW, informational):** the vault's PBKDF2 iteration count is **10,000** (`iterations:1e4`). That is below current OWASP guidance (≥600,000 for PBKDF2-HMAC-SHA256, 2023) and below MetaMask browser-passworder's own hardened default (600,000). Recommend raising it and migrating existing vaults on next unlock. This is a defense-in-depth gap, **not** the critical flaw, and the extension is **not bounty-eligible** (`eligible_for_bounty=false`).

### 3. DeFi Wallet mobile apps (`com.defi.wallet`) — not analyzed
Self-custody, so the pattern *could* apply — but marked **NOT bounty-eligible** in scope, and source isn't readily available for static analysis.

### 4. Main Crypto.com App (`co.mona.android` / `com.monaco.mobile`) — **bounty-eligible (max High)**, not analyzed
This is the eligible asset that now bundles the self-custody "Onchain" wallet. Checking it requires APK decompilation of a large, obfuscated app. **Expected yield for THIS specific flaw is low**, because the Onchain stack appears to be the same modern lineage as the (clean) extension rather than the old desktop-wallet code.

---

## Eligibility map

| Product | Shares the MD5-KDF flaw? | Bounty-eligible? |
|---|---|---|
| Desktop Wallet (v1.5.1) | **Yes** (Medium) | No |
| Onchain/Wallet Extension (v3.10.4) | No (uses PBKDF2+AES-GCM; minor 10k-iter note) | No |
| DeFi Wallet mobile (`com.defi.wallet`) | Unknown (not analyzed) | No |
| Main Crypto.com App (`co.mona.*`) | Unlikely (modern stack) — not analyzed | **Yes** |

## Conclusion
The seed-encryption weakness is **not systemic** — it is confined to the older, non-eligible desktop wallet; the modern extension is sound (bar a minor iteration-count nit). There is therefore **no bounty-eligible target reachable by static analysis** that carries this specific flaw. The desktop-wallet issue remains worth **responsible disclosure** on its own merit. The only route that could turn this into a payable report is confirming the pattern inside the eligible main app's Onchain wallet (APK decompilation), which the extension evidence suggests is unlikely.
