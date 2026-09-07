# Bitmap Bio Wallet Authentication

This is the security-review source for Bitmap Bio profile editing. It is a
non-deployable reference package: it intentionally contains no production
database, ownership cache, image cache, private key, API credential, hosting
configuration, analytics data or user messages.

## What the wallet flow does

1. A visitor chooses UniSat, Xverse or OKX and selects the address currently
   cached as the owner of a Bitmap.
2. The server creates a short-lived, one-time BIP-322 message challenge. It
   binds the domain, address, Bitmap number, nonce and expiry time.
3. The wallet signs that human-readable message. The browser never sends, asks
   for or receives a seed phrase, private key, transaction, PSBT or spending
   permission.
4. The server verifies the signature, stores only a hash of a 30-minute session
   token, and checks cached ownership again before every profile write.

The verifier deliberately fails closed for unsupported address or script types.
The source is for review and testing; it is not a promise that every wallet,
browser extension or firmware release behaves identically.

## Review scope

- `web/` contains browser wallet adapters. They use message-signing APIs only.
- `server/` contains the BIP-322 verification, challenge/session handling,
  profile validation, local image-cache boundary and content moderation hook.
- `tests/` contains public-vector and isolation tests.

## Run the supplied checks

Use Python 3.8+ and Node 18+:

```bash
PYTHONPATH=server python -m unittest tests.test_bio_signature tests.test_lord_bio_auth
node --test tests/test_bio_wallet.cjs
```

## Deployment boundary

Production operators must keep API keys and all `.secret`, database, cache and
log files outside a web-served directory. Do not copy this review package into
a production document root as a deployment recipe. See `SECURITY.md`.

## License

The Bitmap Bio code in this review package is MIT licensed. The BIP340 public
point arithmetic follows the CC0-licensed reference implementation as noted in
the source and security documentation.
