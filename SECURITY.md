# Security policy and threat model

## Safety properties

- No seed phrase, private key, transaction, PSBT, token approval or spending
  permission is requested by the supplied browser code.
- A login signature is domain-, address-, Bitmap-, nonce- and expiry-bound.
- Challenges are single-use. Sessions are origin-bound, short lived and stored
  server-side as hashes only; the browser keeps the raw token in memory only.
- Text is inserted as text rather than HTML. Social links require HTTPS and
  are validated before display.
- Image previews are retrieved only by the server and must become local static
  cache assets before the browser receives a URL.

## Important limits

- Ownership is based on the website's cached Bitmap registry, not a live chain
  query. A transfer is effective after that cache refreshes.
- A malicious browser extension, compromised device, compromised server or a
  visitor who ignores a misleading wallet prompt are outside the guarantees of
  this module. Users should read their wallet's signing prompt.
- This code has tests but has not received an independent professional audit.

## Reporting a vulnerability

Please use a private security advisory in the repository rather than publishing
an exploit or a secret in a public issue. Include reproduction steps, impact and
the smallest affected source area.

## Never commit

Do not commit `.secret`, `.key`, `.pem`, `.env`, database files, API keys,
visitor data, runtime caches, `storage/`, cPanel configuration or server logs.
