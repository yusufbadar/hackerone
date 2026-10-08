# Crypto.com — Static Security Review (HackerOne scope)

**Reviewer:** independent researcher (static source analysis, responsible disclosure)
**Date:** 2026-10-08
**Program:** https://hackerone.com/crypto
**Method:** Static analysis of **public** source only (verified on-chain source + public GitHub repos). No live, active, or intrusive testing was performed against any crypto.com production system.

---

## TL;DR

**No medium-to-critical vulnerability was found. Nothing here is worth submitting as a bounty report.**

The highest-value bounty-eligible on-chain target (CDCETH, extreme tier up to $1M) was audited in depth — by an 8-lens finder sweep plus 3-skeptic adversarial verification, cross-checked by hand. It is a faithful clone of Circle's audited USDC FiatToken plus a trivial, safe exchange-rate oracle wrapper. **Zero exploitable findings.** The reachable DeFi/staking repos are faithful forks of well-audited reference code. Three *informational* design notes are documented below for completeness; none is a payout and I recommend **not** filing them (they mirror accepted cbETH/USDC behavior and would be closed Informative, adding triage noise).

---

## Scope reviewed

| Asset | Type | Bounty-eligible | Reachable here | Result |
|---|---|---|---|---|
| CDCETH impl `LiquidETHV1` `0x7e77…9253` (behind proxy `0xfe18…c38e`, Ethereum) | Smart contract | ✅ up to $1M | ✅ verified source | **No exploitable bug** |
| CDCBTC `0x2e53…495d` (Cronos) | Smart contract | ✅ critical | ⚠️ impl source gated | Identified only (see below) |
| `crypto-com/swap-contracts-core` | Source | ❌ | ✅ | Clean (Uniswap V2 fork) |
| `crypto-com/swap-contracts-periphery` | Source | ❌ | ✅ | Clean; 1 low latent note |
| `crypto-com/cro-staking` | Source | ❌ | ✅ | Clean (ERC900 reference) |

---

## CDCETH (`LiquidETHV1`) — primary target

**Architecture.** The proxy `0xfe18ae03741a5b84e39c295ac9c856ed7991c38e` is Circle's `FiatTokenProxy` (EIP-1967). Its implementation `0x7e772ed6e4BfEAE80f2d58e4254f6b6e96669253` is `LiquidETHV1`: lines 22–2148 are a **verbatim copy of Circle/CENTRE FiatToken (V2_1-era)** — the exact code that backs USDC — and lines 2188–2285 are the only crypto.com-authored logic, a thin cbETH-style wrapper adding an exchange-rate oracle.

**Why it's clean (verified, not assumed):**
- The custom `exchangeRate` is **never read by any `mint` / `burn` / `_transfer` / `approve` / EIP-3009 / EIP-2612 path** in this contract. CDCETH is a non-rebasing ERC20; balances and `totalSupply` are independent of the rate. A wrong/malicious rate **cannot move this token's own balances**.
- Every privileged action is correctly role-gated and matches the documented trust model (minter/masterMinter/pauser/blacklister/owner/oracle). No path lets an **unauthorized** actor mint, move, or freeze funds.
- `SafeMath` guards arithmetic; `ECRecover` enforces low-`s` and `v ∈ {27,28}` (no signature malleability); EIP-3009/EIP-2612 nonces prevent replay; `receiveWithAuthorization` has the `to == msg.sender` front-running guard.
- Drift from canonical V2_2 is benign (V2_2 adds EIP-1271 smart-wallet sig support and per-chainId domain-separator recomputation; neither absence is a defect in the correct V2_1 logic deployed here).

### Informational notes (NOT bounty-worthy — documented for completeness)

**INFO-1 — Oracle rate update is unbounded/un-timestamped/instant** (CVSS 3.7, `AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:N`).
`updateExchangeRate` only checks `newExchangeRate > 0`; no ceiling, no max-deviation, no timelock, no stored timestamp. Because the value is inert inside CDCETH, the only exposure is to **external** integrators that price CDCETH off `exchangeRate()`, and only if the **trusted oracle/owner key** is compromised or fed a bad value. This is a centralization/integration-safety property identical to cbETH, not an unauthorized-actor exploit.
*Hardening:* store+expose a `lastUpdated` timestamp; bound per-update deviation; route updates through a timelock/multisig; document integration guards.

**INFO-2 — `DOMAIN_SEPARATOR` cached at init (V2_1)** (CVSS 2.6, `AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N`).
The separator is computed once in `initializeV2` and frozen, so gasless-signature paths could be cross-chain-replayed **only after a contentious persistent hard fork** that changes chainId while preserving state. This is the accepted behavior of every V2_1-era USDC fork; probability is very low and outside any attacker's control. (Also means EIP-1271 contract wallets can't use permit/authorization — a functionality limit, not a security loss.)
*Hardening:* upgrade to the V2_2 pattern (recompute separator when `block.chainid` changes; adopt `SignatureChecker`).

**INFO-3 — Implementation initializers not locked** (CVSS 0.0, non-exploitable).
Anyone can `initialize` the bare implementation contract and own **its own unused storage**, but the proxy holds all production state and the implementation has no `delegatecall`/`selfdestruct`, so the proxy and all users are unaffected. Standard FiatToken/cbETH property.
*Hardening (optional hygiene):* add a constructor that locks the implementation (`initialized = true`).

---

## CDCBTC (`0x2e53…495d`, Cronos) — bounty-eligible, partially reachable

Identified via public RPC as **"Crypto.com Wrapped BTC" (CDCBTC)**, 8 decimals. It is a `FiatTokenProxy` (legacy zeppelinos impl slot → impl `0xddcde8de19284cc5aab6db5ac6af1dcda175f5e2`) but **without** the LiquidETH oracle extension (`exchangeRate()`/`oracle()` revert) — i.e. a plainer FiatToken clone of the same audited Circle base. Its Cronos-side verified source sits behind the auth-gated Cronos Blockscout API (Cronoscan is unreachable from this environment), so a byte-accurate diff of its implementation was not possible here. Its shared Circle base is covered by the CDCETH audit. **To finish this one, paste its verified source from the Cronos explorer and I'll diff the delta.**

---

## DeFi / staking repos (not bounty-eligible, reviewed anyway)

- **`swap-contracts-core`** — Uniswap V2 fork (`CroDefiSwap*`). The configurable-fee generalization (`magnifier=10000`, `totalFeeBasisPoint ≤ 50 bps`) is implemented consistently in `swap()` and `_mintFee()`; reentrancy `lock`, `permit` zero-address check all intact. **No bug.**
- **`swap-contracts-periphery`** — standard Router02 + library. One **low-severity latent note**: `CroDefiSwapLibrary.getAmountOut/In` hardcode `997/1000` (0.3%) while the pair enforces the configurable fee; if the fee were ever changed, router-quoted swaps would mostly **revert** (safe failure) or marginally underpay LPs — not fund loss.
- **`cro-staking`** — verbatim ERC900 reference implementation; `totalStakedFor` accounting is balanced and FIFO withdrawal (`personalStakeIndex`) prevents double-withdraw. **No bug.**

---

## Methodology

1. Scope parsed from the program's structured scope export.
2. Public source obtained via keyless explorers (Blockscout/Sourcify) and anonymous GitHub clones. No authenticated access, no transactions, no probing of live web/API assets.
3. CDCETH audited with a multi-agent workflow: **8 independent lenses** (access control, mint/burn/supply, EIP-3009, EIP-2612, blacklist/pause, proxy/init, oracle, canonical-diff) → candidate findings → **3 adversarial skeptics per candidate (majority-survives)** → synthesis. Cross-checked by hand against Circle's canonical repo.
4. Result: **0 candidates survived adversarial verification.**

## Conclusion

The safely-analyzable public code in scope is sound. The honest, responsible outcome is **no submission** — filing the informational notes would be noise. Making users safer here is best served by this clean bill of health plus the optional hardening suggestions above, not by a report for its own sake.
