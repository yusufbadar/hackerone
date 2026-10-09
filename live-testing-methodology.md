# Crypto.com Bug Bounty — Rules-First Live-Testing Methodology

**Purpose:** a safe, program-compliant plan for testing the **bounty-eligible** web / exchange / API assets, where the real Medium–Critical payouts live. 
**Division of labor:** *you* run any live interaction (logged into your own accounts, in a browser / proxy on your machine). *I* help design tests, interpret responses you paste back, and turn confirmed issues into submission-ready reports. I don't send traffic to production systems.

> ⚠️ **Read the live policy first.** This environment can't reach `hackerone.com`, so the rules below are reconstructed from the scope export + standard program norms. **Before testing, open https://hackerone.com/crypto and confirm the authoritative Policy / "Out of Scope" / rules sections.** If anything here conflicts with the live policy, the live policy wins.

---

## 1. Rules of engagement (do this first — it protects you and real users)

**Always:**
- Test **only** against assets marked eligible (Section 2), using **your own accounts / test data**.
- Create dedicated test accounts. Keep a second throwaway account to safely test cross-account access (IDOR/authz) **against your own two accounts only**.
- Tag your traffic so triage can identify it: a custom `User-Agent` (e.g. `h1-<yourusername>-research`) and, where a field allows, your H1 handle.
- Throttle. Hand-crafted requests and small, targeted checks only.
- Stop immediately and report if you ever get access to **another real user's data** — do not pivot, download, or enumerate further. Capture the minimum proof.

**Never (these get you banned and can harm users):**
- No DoS / stress / load / volumetric testing. (Note: even *reward-eligible* GraphQL-DoS findings are reward-capped — see Section 6 — and should be demonstrated by reasoning/single-request evidence, not by actually degrading service.)
- No automated aggressive scanners/fuzzers against production (no mass spidering, no high-RPS brute force). Low-and-slow, targeted, manual.
- No social engineering, phishing, or physical attacks.
- No accessing, modifying, or exfiltrating other users' data beyond the minimal proof of a single instance.
- No testing of third-party services, or assets not listed as eligible.
- Don't run real-money transactions you can't reverse to "prove" a bug; model the logic and show the flaw with the smallest safe step.

---

## 2. Eligible scope & severity caps (from the scope export — verify live)

| Asset | Type | Max severity | Notes |
|---|---|---|---|
| `crypto.com/exchange` | Web | Critical | |
| `web.crypto.com` | Web | Critical | |
| `app.mona.co` | Web | Critical | |
| `*.crypto.com` / `*.mona.co` | Wildcard | Critical | subdomain takeover, forgotten hosts |
| `js.crypto.com` | Web | Critical | |
| `merchant.crypto.com` | Web | — | **GraphQL DoS reward capped $200** |
| `crypto.com/nft` | Web | Critical | **GraphQL DoS reward capped $500** |
| `crypto.com/price` | Web | Medium | lower cap |
| `tax.crypto.com` | Web | Critical | **Critical & High only** |
| `nadex.com` | Web | Medium | **Critical & High only** |
| `og.com` | Web | Critical | |
| `travel.`/`experiences.`/`tickets.crypto.com` | Web | Critical | newer, less-trodden surface |
| `developer.crypto.com`, `developer-api.crypto.com`, `developer-platform-api.crypto.com` | Web/API | Critical | |
| Crypto.com **mobile app APIs** that require an account (incl. BFF) | API | Critical | needs a logged-in account |
| Crypto.com **Exchange APIs** that require an account (incl. BFF) | API | Critical | needs a logged-in account |
| `co.mona.android` / `com.monaco.mobile` | Mobile app | High | the main app |

Out-of-scope for bounty (do **not** submit as paid): `com.defi.wallet`, the Wallet/Onchain Extension, `chain-desktop-wallet`, the swap/staking repos. (Real issues there are still worth **responsible disclosure**, just not paid.)

---

## 3. Where the real money is — prioritized bug classes

Ranked by expected payout density for a crypto platform. For each: what to look for, and the **safe** way to confirm.

### A. Broken access control / IDOR on account & BFF APIs  *(highest value)*
The account-gated mobile/exchange BFF APIs are explicitly in scope at **Critical**. These aggregate many backend calls and are a classic source of authz gaps.
- With **two of your own accounts**, capture a request that references an object id (orderId, walletId, txId, documentId, deviceId, ticketId). Replay it from account B against account A's id. Access to A's data from B = IDOR.
- Look for: numeric/sequential ids, UUIDs leaked in other responses, `GET`/`POST` where the server trusts a body/param id over the session.
- Also: missing function-level authz (calling an admin/privileged endpoint as a normal user), and tenant/role confusion.

### B. Business-logic flaws in money movement
- Negative/overflow amounts, rounding/precision abuse, race conditions on balance-changing actions (withdraw/transfer/convert/claim), replayable state-changing requests, inconsistent validation between the UI and the API.
- Confirm with the **smallest** reversible step against your own account; model the rest.

### C. Authentication / session / account-takeover
- OTP/2FA bypass or brute-force (without volumetric abuse), password-reset token predictability/leakage, session fixation, JWT issues (alg confusion, weak/absent signature validation, long-lived tokens), OAuth redirect_uri / state problems, login CSRF.

### D. SSRF (very high value on API/integration surfaces)
- Any feature that fetches a URL you control (webhooks, avatar/image import, link preview, merchant callbacks, KYC document fetchers, dApp/price integrations). Test with a collaborator host you own; look for internal metadata access (`169.254.169.254`) via the response/timing.

### E. GraphQL (merchant, nft, others)
- Introspection enabled? Over-permissive queries returning other users' data? Missing field-level authz? Batching/alias abuse.
- **DoS is reward-capped** (merchant $200 / nft $500) and must not actually degrade service — demonstrate with a single crafted query + reasoning, not a flood.

### F. Injection & XSS
- Stored/reflected XSS on user-content surfaces (nft metadata/names, profile fields, merchant data, support/ticket fields), template injection, SQL/NoSQL injection on filter/search params.

### G. Wildcard-only wins
- `*.crypto.com` / `*.mona.co`: **subdomain takeover** (dangling CNAMEs to deprovisioned SaaS), exposed staging/debug hosts, `.git`/env file exposure, default creds on forgotten services.

### H. Newer surfaces (travel / experiences / tickets / og)
- Less battle-tested; prioritize A–F there. Booking/ticket flows often have business-logic and IDOR gaps.

---

## 4. Suggested session setup (on your machine)
- An intercepting proxy (Burp/ZAP/mitmproxy) with a scope allowlist set to **only** the eligible hosts, so you can't accidentally hit out-of-scope targets.
- Two test accounts (A, B). Record ids/tokens for cross-account checks.
- Logging on, so every request/response is saved as evidence.
- Custom `User-Agent` identifying you as a researcher.

## 5. Findings capture → hand to me for write-up
For anything interesting, paste me:
1. Asset + endpoint (method + path), and which account/role.
2. The request (redact **your** secrets) and the relevant response snippet.
3. What you expected vs what happened, and why it's a security impact.
4. Repro steps.

I'll verify the logic, assign CVSS, classify impact, confirm it's in scope and above the asset's severity floor, and produce a submission-ready report (like `finding-wallet-seed-encryption.md`). I'll also flag anything likely to be a duplicate or informative so you don't burn triage goodwill.

## 6. Reward-cap / floor reminders
- `merchant.crypto.com` GraphQL DoS → **$200 cap**; `crypto.com/nft` GraphQL DoS → **$500 cap**.
- `tax.crypto.com` and `nadex.com` → **only Critical & High** accepted.
- `crypto.com/price` → **Medium** max.
- Everything else eligible → up to **Critical**.

---

### Honest expectation-setting
Most value here is **authz/IDOR on the account APIs, business-logic on money movement, and SSRF** — all of which need a logged-in session and careful manual testing that you drive. I'll make every confirmed observation into a clean, high-quality report. We lead with correctness and restraint: a few well-verified, in-scope findings beat a pile of noise, and they keep you in good standing with the program.
