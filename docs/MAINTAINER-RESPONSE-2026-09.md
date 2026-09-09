# Maintainer response: wallet-auth security review

This response addresses the public review in pull request #1. The implementation here is deliberately a separate, reviewable change rather than an automatic merge of every suggested pull request.

## Included in this response

- **M-1:** Adds a local RIPEMD160 fallback when the host OpenSSL configuration does not offer it through `hashlib`, preserving P2WPKH (`bc1q`) verification.
- **M-2:** Checks the profile save cooldown before any image resolution and limits each Lord to 25 inscription-image lookups per rolling day. This is an upper bound for one Lord, not a replacement for the existing site-wide provider budget.
- **M-3:** Binds every editing session to the Bitmap named in the signed message. Sessions created before this migration intentionally stop authorizing writes.
- **M-4:** The browser validates the origin, address, Bitmap and nonce in the challenge before handing the message to a wallet.
- **L-1:** Closing the editor best-effort revokes its server-side session.
- **L-2:** Loopback origins require `BITMAPADS_DEV_ORIGINS=1`; production leaves that variable unset on every operating system.
- **L-4:** Shared secrets are created with exclusive creation so concurrent workers converge on one key rather than caching different values.
- **L-5:** Every guestbook read path is re-evaluated using the current moderation policy, including the main per-Lord message list.

## Deliberately not included

### L-3 / PR #8: `smp` transport-prefix removal

The repository's current BIP-322 vectors fail when that compatibility path is removed. A prefix does not bypass witness or signature verification: the decoded witness still undergoes the same strict validation. It remains until real wallet interoperability is demonstrated without it and a replacement end-to-end vector is available.

### L-6 / PR #11: Jacobian-coordinate rewrite

The reported performance improvement is valuable, but this is cryptographic core code. It is intentionally deferred for a dedicated review that includes independent vector checks on the actual shared-host Python runtime. Availability optimization must not trade away verifier correctness.

### 503 / challenge consumption behavior

The RIPEMD160 fallback resolves the concrete host-availability failure. The broader proposal to return 503 without consuming a challenge needs a separate design: invalid signatures must remain one-use to prevent replay and repeated verification work, while genuine server failures must be distinguishable without creating a retry-amplification path.

## Validation performed

On the current application code: Python wallet, Bio backend/auth and asset tests; the browser-side Bio test; syntax compilation; and an RIPEMD160 fallback known vector all passed. This change should still be tested in the target Passenger/cPanel runtime before production deployment.
