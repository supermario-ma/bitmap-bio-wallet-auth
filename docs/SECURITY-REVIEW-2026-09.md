# Independent security review — wallet connection, session and asset safety

**Target:** `supermario-ma/bitmap-bio-wallet-auth` @ `769d118`
**Date:** 2026-09-07
**Scope:** `web/bio-wallet.js`, `server/bio_signature.py`, `server/lord_bio_auth.py`,
`server/lord_bio.py`, `server/inscription_assets.py`, `server/moderation_policy.py`, `tests/`
**Method:** full manual read of all 2,252 lines, execution of the supplied suite
(13/13 passing), plus targeted differential and timing probes against the
BIP-322 vectors in `tests/fixtures/`.

This review was performed without access to the HTTP layer, the production
database, the reverse proxy or the deployment configuration. Findings that
depend on those layers are marked as **deployment boundary** rather than
assumed to be broken.

---

## 1. Headline answer on asset safety

**No path was found from this authentication flow to a loss of Bitcoin, an
inscription, or any spendable asset.** This is a structural property, not a
matter of careful coding, and it is worth stating precisely because it is the
question that matters most:

1. The browser code calls message-signing APIs only. There is no `signPsbt`,
   no `sendBitcoin`, no `pushTx`, no token approval and no spending permission
   anywhere in `web/bio-wallet.js`. `tests/test_bio_wallet.cjs:20` asserts this
   at build time, which is the right way to keep it true.
2. BIP-322 signing is domain-separated from transaction signing by the
   `BIP0322-signed-message` tagged hash (`server/bio_signature.py:99`). A
   signature produced here is not a valid signature over any real transaction.
3. The virtual `to_spend` transaction commits to a null prevout
   (`00…00:0xFFFFFFFF`, `server/bio_signature.py:100`), an output that can
   never exist on-chain outside a coinbase. The `to_sign` sighash therefore
   commits to a prevout, an amount of 0 and an `OP_RETURN` output that no real
   spend can reproduce. Cross-context replay onto a live UTXO is not possible.

The residual asset risk lives entirely outside this module: a user signing on a
look-alike site, a malicious browser extension, or XSS on the real origin.
Section 5 addresses the first of those, which is the one the project can still
meaningfully reduce.

---

## 2. What this codebase already gets right

Several of these are things production dApps routinely get wrong, and they
should not be lost in a future refactor:

- **The signed message is never taken from the client.** `verify` reads
  `row["message"]` from the challenge row (`server/lord_bio_auth.py:115`), not
  from the request body. This single decision eliminates the most common
  wallet-authentication vulnerability class, in which an attacker supplies both
  the message and a matching signature.
- **The challenge is consumed before verification**, in its own committed
  transaction (`server/lord_bio_auth.py:113-114`). One attempt per challenge,
  including failed ones, so there is no repeated-attempt oracle.
- **Ownership is re-checked after the signature verifies** (`:118`) and **again
  after the image lookup**, inside `BEGIN IMMEDIATE` (`:142`). Both TOCTOU
  windows are closed.
- **Session tokens are 256-bit, stored only as SHA-256 digests, and never
  placed in `localStorage`.** Because they travel in an `Authorization` header
  rather than a cookie, the write endpoints are structurally immune to CSRF.
  A missing or unknown `Origin` fails closed (`:20-25`).
- **Signature-level hardening is genuinely strict.** Low-S is enforced
  (`server/bio_signature.py:117` — confirmed experimentally: a re-encoded
  high-S variant of a valid vector is rejected), DER parsing is minimal-form,
  trailing witness bytes are rejected, and `SIGHASH` is restricted to
  `ALL`/`DEFAULT`. Unsupported address and script types fail closed rather than
  defaulting to accept.
- **The BIP-143 and BIP-341 sighash preimages are byte-correct**, and the
  BIP-340 `lift_x` even-Y convention is right. Verified against the public
  vectors and the `to_spend` transaction-hash vectors.
- **Raw IPs are never stored** — they are HMAC'd with a server-side secret
  before use as a rate-limit key (`server/lord_bio_auth.py:92`).

---

## 3. Findings

Severity reflects impact on this system as deployed, not CVSS.

| # | Severity | Area | Finding |
|---|----------|------|---------|
| M-1 | Medium | Availability | `hashlib` RIPEMD-160 can be absent at runtime; every `bc1q` login then fails, indistinguishably from a bad signature |
| M-2 | Medium | Availability | One authenticated owner can exhaust the site-wide monthly image-API quota in minutes |
| M-3 | Medium | Authorization | Session scope is broader than the scope the user consented to in the signed message |
| M-4 | Medium | Client | The browser signs whatever the server returns, with no validation |
| L-1 | Low | Session | No sign-out; a valid session survives closing the editor |
| L-2 | Low | Config | Origin allow-list has a development bypass keyed on the host OS |
| L-3 | Low | Hygiene | Production verifier accepts a prefix that exists only in this repo's test fixtures |
| L-4 | Low | Concurrency | Secret-creation race across worker processes |
| L-5 | Low | Consistency | Guestbook moderation is re-applied on two read paths but not the third |
| L-6 | Low | DoS | Pure-Python secp256k1 costs ~60 ms per verification |

### M-1 — RIPEMD-160 may be unavailable, and the failure is silent

`server/bio_signature.py:141` calls `hashlib.new("ripemd160", …)` to bind the
witness public key to the address program. OpenSSL 3 moved RIPEMD-160 to the
legacy provider, which is not enabled by default on a number of common
distributions; `hashlib.new("ripemd160")` then raises `ValueError`.

That `ValueError` is caught by the blanket handler at
`server/bio_signature.py:152` and returned as `False`. The consequences chain
badly:

- **Every** native-SegWit (`bc1q`) login fails, on every attempt. Taproot
  (`bc1p`) still works, so the fault presents as "some users can't log in".
- The user is told *"Wallet signature could not be verified. Please reconnect
  using the owning address."* — which is actively misleading, and will send
  people to re-check their wallet, or worse, to a support channel where they
  can be socially engineered.
- The challenge was already consumed at `server/lord_bio_auth.py:113`, so each
  retry burns another challenge until the 20-per-10-minutes limit
  (`:94`) locks the user out entirely.

This is a fail-closed outcome, so it is not a bypass — but it is an
availability and diagnosability defect, and the environment on a shared cPanel
host is exactly the sort the operator does not control.

**Recommendation.** Vendor a small pure-Python RIPEMD-160, as Bitcoin Core did
for the same reason in [bitcoin/bitcoin#23716](https://github.com/bitcoin/bitcoin/pull/23716),
and fall back to it when `hashlib` refuses. Separately, do not let environment
faults be indistinguishable from invalid signatures: raise a distinct internal
error, log it, return a 503 rather than a 403, and **do not consume the
challenge** when verification could not be performed at all.

### M-2 — A single authenticated user can exhaust the shared image quota

`server/inscription_assets.py:159` sets a global budget of **950 Ordiscan calls
per month** and 90 per minute, shared by the whole site.

The `avatar` action has **no rate limit of its own**. The only throttle in
`handle` is the 5-second profile-save cooldown at
`server/lord_bio_auth.py:144` — and the resolver is invoked at `:133`,
*before* that check runs. So the cooldown protects the database write, not the
upstream API.

Any authenticated Bitmap owner can therefore loop `avatar` (or even `save`)
with distinct inscription numbers, each a cache miss, and drain the monthly
budget in roughly eleven minutes at the per-minute ceiling. Every subsequent
avatar lookup site-wide then fails with `AssetError('quota')` until the
calendar month rolls over. Negative caching does not help: misses are cached
for only 30–300 seconds, and distinct numbers do not collide.

**Recommendation.** Add a per-session and per-address counter for resolver
invocations (a small daily cap is enough), move the cooldown check *above* the
resolver call, and consider a separate, smaller per-address slice of the
monthly budget so one account cannot consume the shared pool.

### M-3 — Session scope exceeds the consented scope

The challenge message the user reads and signs is explicitly scoped to one
Bitmap:

```
Bitmap: <n>.bitmap
...
URI: <origin>/<n>
```

The session row that results from it is not. `lord_bio_sessions` stores only
`(token_hash, lord_address, origin, expires_at)`
(`server/lord_bio_auth.py:120`, schema at `server/lord_bio.py:208-210`), and
`_session` authorises on `lord_address` alone (`:48`). A session obtained by
signing for Bitmap #1 is accepted for every other Bitmap the same address owns,
and confers the `lord` author role in the guestbook
(`server/lord_bio.py:223`), which carries a 20-second posting cooldown instead
of the visitor's 20 minutes.

Because profiles are keyed by address rather than by Bitmap, the practical
impact today is small. The defect is that **the message misrepresents what the
signature authorises**, which is precisely the property a signed-in-with-wallet
message exists to establish. It also becomes a real authorization bug the
moment per-Bitmap state is introduced.

**Recommendation.** Either add `bitmap_number` to `lord_bio_sessions` and check
it in `_session`, or change the message to state the true scope. SIWE's
`Resources` field exists for exactly this and is the cleaner fix
(see §5).

### M-4 — The browser signs whatever the server returns

`web/bio-wallet.js:44` does:

```js
const challenge = await api('challenge', {address: current.lord});
…
const signature = await sign(challenge.message);
```

`challenge.message` is displayed (safely, via `textContent`) inside a collapsed
`<details>` element and then handed to the wallet unexamined. The client never
checks that the message it is about to have signed mentions the current origin,
the expected address, the expected Bitmap number, or the nonce it received.

The server is trusted here, so this is defence-in-depth rather than a live
vulnerability. But it is the one control that would still hold if an API
response were tampered with in transit, mis-routed by a proxy or CDN, or served
by a compromised backend — and it costs about six lines. It also protects
against the more mundane case of a stale or mismatched deployment.

**Recommendation.** Before calling `sign()`, assert that `challenge.message`
starts with `location.origin + ' requests a Bitmap Lord Bio sign-in.'`,
contains `Address: ${owner}`, `Bitmap: ${number}.bitmap`,
`Nonce: ${challenge.nonce}`, and is under a fixed length. Refuse to sign
otherwise. Surface the message expanded by default rather than behind
`<details>` — the user reading it is the last line of defence, and the current
UI hides it.

### L-1 — No sign-out

There is no action that invalidates a session. `handle` accepts only
`challenge`, `verify`, `save` and `avatar` (`server/lord_bio_auth.py:87,107,123`);
rows are deleted only once they are more than a day past expiry, and only as a
side effect of somebody else requesting a challenge (`:104`).

On the client, `dialog.close()` does not clear `session`
(`web/bio-wallet.js:41`), so reopening the editor within 30 minutes
re-authenticates with no new signature (`:57-58`). On a shared or public
machine, closing the panel looks like logging out and is not.

**Recommendation.** Add a `logout` action that deletes the session row by
token hash, call it from a visible "Disconnect" control, and clear the
in-memory `session` on dialog close.

### L-2 — Origin bypass keyed on the host operating system

```python
if os.name == "nt" and re.fullmatch(r"http://(127\.0\.0\.1|localhost):[0-9]{2,5}", value or ""):
    return value
```
`server/lord_bio_auth.py:24`

The comment — *"never enable loopback origins on the Linux host"* — is doing
the work that a configuration flag should be doing. The control is correct only
for as long as production never runs on Windows. That is an assumption about
hosting, enforced nowhere, in a file that will outlive the assumption.

**Recommendation.** Gate on an explicit opt-in (`BITMAPADS_DEV_ORIGINS`, absent
in production) rather than on `os.name`, and keep `ALLOWED_ORIGINS` in
configuration rather than in source.

### L-3 — Production verifier accepts a test-fixture prefix

`server/bio_signature.py:85` strips a leading `"smp"` before base64-decoding.
No wallet produces this. It is a convention of this repository's own fixtures,
which tag vectors by proof type — `smp` for simple, and the error vectors show
`ful` and `foo` as the rejected counterparts.

The practical risk is negligible: a well-formed BIP-322 simple witness always
base64-encodes to a leading `A`, so no genuine signature collides with the
prefix. The objection is one of principle — production input validation should
not carry an affordance that exists only for the test harness, and a reader
auditing this file has no way to know that is what it is.

**Recommendation.** Strip the prefix in `tests/test_bio_signature.py` and
delete line 85.

### L-4 — Secret-creation race across workers

`server/lord_bio.py:46-77` reads a secret, and on `OSError` generates a new one
and `os.replace`s it into position. Under a multi-process server (Passenger,
mod_wsgi, gunicorn), two workers starting concurrently can both miss, both
generate *different* secrets, and both write. `os.replace` is atomic, so the
file ends up with one of them — but the loser has already cached its own value
in `_SECRET_CACHE` (`:76`) and will keep using it for the life of the process.

The consequences are quiet rather than dramatic: `ip_hash` values diverge
between workers, so the 20-per-10-minutes challenge limit is effectively
multiplied by the number of divergent workers; and guestbook cookies signed by
one worker fail validation on another.

Separately, `path.parent.mkdir(parents=True, exist_ok=True)` at `:62` does not
pass `mode=0o700`, unlike `Resolver.connect` at
`server/inscription_assets.py:149`, so the directory holding the secret may be
created with default permissions.

**Recommendation.** Create with `os.open(path, O_CREAT|O_EXCL|O_WRONLY, 0o600)`
and, on `FileExistsError`, re-read the winner's value instead of caching your
own. Pass `mode=0o700` to `mkdir`.

### L-5 — Moderation is re-applied on two read paths but not the third

`guestbook_preview` (`server/lord_bio.py:355`) and `guestbook_latest` (`:385`)
both re-run `_message()` — and therefore the current moderation policy — over
stored text before returning it. `guestbook_get` (`:436`) returns
`row["text"]` verbatim.

Text is moderated at write time, so this only matters when the policy changes:
newly added terms take effect on the map preview and the global feed, but not
on the main per-Lord list, which is the largest surface. Given that
`resources/moderation/political-focus-v1.json` is explicitly versioned, policy
updates are clearly an expected event.

**Recommendation.** Apply `_message()` on the `guestbook_get` path too, or
re-moderate stored rows on policy version change. Also note `MAX_PAGE_SIZE`
(`server/lord_bio.py:25`) is defined but never used.

### L-6 — Verification cost

The pure-Python secp256k1 implementation uses affine coordinates with a modular
inversion (`pow(x, P-2, P)`) on every point addition. Measured on CPython 3.13:

| Path | Per verification | Throughput |
|------|------------------|------------|
| P2WPKH (ECDSA) | 58.9 ms | ~17 /s /core |
| P2TR (Schnorr) | 62.6 ms | ~16 /s /core |

Reaching that code requires a valid unused nonce, so the challenge limiter caps
a single source at 20 verifications per 10 minutes — about 1.2 s of CPU. The
exposure is therefore distributed rather than single-source: roughly 500
addresses would saturate one core continuously, which is inexpensive to arrange.
On a shared host with one or two cores this is a realistic availability concern,
and the same work is being done ~100× slower than necessary in the normal case.

**Recommendation.** Use `coincurve` (libsecp256k1) when importable and keep the
pure-Python path as the fallback it was designed to be. Add a rate limit on
`verify` keyed on the same IP hash, independent of the challenge limiter.

---

## 4. Deployment-boundary notes

These cannot be assessed from this package but determine whether the controls
above hold. They belong in `SECURITY.md`.

- **`remote_ip` provenance.** Every rate limit in `lord_bio_auth.py` and
  `lord_bio.py` is keyed on it. If the HTTP layer takes it from
  `X-Forwarded-For` without a trusted-proxy allow-list, all of them are
  bypassable by header spoofing. If it is instead a CDN edge IP shared by many
  users, the 20-per-10-minutes limit becomes a site-wide outage. Document which
  proxy is trusted and how many hops are stripped.
- **Request size and method.** `handle`'s docstring says *"Caller enforces
  bounded UTF-8 JSON request size"* — state the bound, and confirm the route is
  POST-only.
- **`Content-Security-Policy`.** The session token lives in JavaScript memory
  by design, which makes XSS on the origin the highest-value attack against
  this flow. A strict CSP (no `unsafe-inline`, explicit `connect-src`) is the
  control that matters most and is not mentioned anywhere in the repository.
- **`Cache-Control: no-store`** on the `challenge` and `verify` responses.
- **`onAuthenticated(token)`** (`web/bio-wallet.js:44`) hands the raw token to
  host-page code that is not in this package. `SECURITY.md` claims the browser
  keeps it in memory only; that claim is only as good as that callback.

---

## 5. Comparison with mainstream wallet-connection practice

| Dimension | This project | Mainstream practice |
|---|---|---|
| **Message format** | Ad-hoc prose | [EIP-4361 / SIWE](https://eips.ethereum.org/EIPS/eip-4361), [CAIP-122 SIWx](https://standards.chainagnostic.org/CAIPs/caip-122) — fixed field order: domain, address, URI, version, nonce, issued-at, expiration-time, resources |
| **Domain binding** | Server-side only | The structured first line lets the **wallet** compare the message's domain against the request origin and warn on mismatch |
| **Provider discovery** | Direct `window.unisat` / `window.okxwallet.bitcoin` / `window.XverseProviders` sniffing | [WBIP-004](https://docs.xverse.app/sats-connect/wallet-providers) `window.btc_providers` registry, via [sats-connect](https://github.com/secretkeylabs/sats-connect) or [LaserEyes](https://www.lasereyes.build/) |
| **RPC surface** | Bespoke call per wallet | WBIP-001 `wallet.request` JSON-RPC 2.0 |
| **Signature verification** | Hand-rolled pure-Python secp256k1 | libsecp256k1 bindings (`coincurve`), `@noble/curves` |
| **Nonce / replay** | Single-use, expiring, server-stored message | Equivalent — **this project is at or above the common standard here** |
| **Session** | Bearer, hashed at rest, 30 min | Equivalent, plus explicit sign-out and rotation |
| **Address coverage** | `bc1q` P2WPKH and `bc1p` P2TR only | Usually adds P2SH-P2WPKH (`3…`), legacy (`1…`), BIP-137 fallback |

Two of these are worth acting on, and the rest are informational.

**Adopt the SIWE/CAIP-122 line format.** This is the highest-leverage change in
the review. The current message is readable prose, which is good for the human
but invisible to tooling. The SIWE convention exists because wallets are
required to check it: when a message begins `example.com wants you to sign in
with your …`, a conforming wallet verifies the request actually came from
`example.com` and warns otherwise. Prose cannot be checked, so the entire
anti-phishing burden falls on the user noticing a wrong domain in a collapsed
`<details>` panel. Restructuring the message costs nothing on the server — the
verifier already signs whatever string is stored — and moves domain binding
from "server-side only" to "enforceable by every conforming wallet". It also
gives M-3 a natural home in the `Resources` field.

**Move to WBIP-004 provider discovery.** Sniffing `window.unisat` means
whichever extension injected last wins, and any extension can squat the global.
Server-side signature verification means a squatter still cannot forge a login
— it cannot produce a signature for the owning address — so this is a UX and
phishing-surface issue rather than an authentication bypass. But
`window.btc_providers` lets the user pick a provider by its declared identity,
which is materially better when several wallets are installed. Relatedly, the
adapters register no `accountsChanged` or `networkChanged` listeners, so
switching accounts mid-session leaves stale UI; the server catches the
mismatch, but the user sees a confusing error rather than a prompt to reconnect.

---

## 6. Test-suite observations

The suite is well-targeted for its size — 13 tests, all passing, and the
assertions in `tests/test_bio_wallet.cjs:20` that the client contains no
`localStorage`, `signPsbt` or `sendBitcoin` are a genuinely good pattern.

The significant gap: `tests/test_lord_bio_auth.py:28` patches
`bio_signature.verify` to return `True` for every authenticated test. The
integration between `handle("verify")` and the real verifier is therefore never
exercised. `tests/fixtures/bip322/generated.json` already contains addresses,
messages and valid signatures — pointing `bitmap_registry.owner_address` at a
fixture address and replaying its real signature end-to-end would close this
with a few lines, and would have caught M-1 on any host lacking RIPEMD-160.

Also untested, in rough priority order: low-S rejection (implemented, verified
by hand during this review, but unguarded against regression); challenge expiry
(session expiry *is* covered); the 20-per-10-minutes limiter; a missing or
empty `Origin`; and `bc1q` P2WPKH end-to-end through `handle`, which is the
path M-1 breaks.

---

## 7. Suggested priority

1. **M-1** — add the RIPEMD-160 fallback, stop consuming the challenge when
   verification could not be performed, and add the end-to-end `bc1q` test.
2. **M-2** — per-address cap on resolver calls; move the cooldown above the
   resolver.
3. **M-4** and the SIWE message format (§5) — best done together, since both
   touch the challenge string.
4. **M-3**, **L-1** — session scope and sign-out.
5. **L-2** … **L-6**, and the `SECURITY.md` additions in §4.

None of the findings above indicate that user funds are at risk through this
module. The design decisions that matter most — message-signing only,
server-stored challenge text, single-use challenges, re-checked ownership —
are sound, and the review's recommendations are about hardening the edges
around them rather than repairing the core.

---

*Review performed against commit `769d118`. Timing figures measured on CPython
3.13.6. Findings are reported as observed; where a conclusion depends on layers
outside this package, that dependency is stated rather than assumed.*
