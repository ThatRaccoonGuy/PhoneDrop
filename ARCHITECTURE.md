# PhoneDrop architecture

A single-file Python server (`phonedrop.py`, standard library only) plus a static web panel
(`static/`). No framework, no build step, no npm. Everything a phone or the PC does goes through the
same HTTP API; the only difference is which listener the request came in on.

```
 phone  ──HTTPS :8443 (LAN IP, self-signed leaf cert)──┐
                                                        ├──► Handler (one thread per request)
 PC     ──HTTP  :8080 (127.0.0.1 only)─────────────────┘        │
                                                                 ▼
                                                 State  (sessions, notes, files, settings)
                                                   │  Clipper  (background PNG conversion for Copy)
                                                   │  Hasher   (background SHA-256 of received files)
                                                   │  cleanup  (optional --keep-days sweeper)
                                                   ▼
                            ~/Pictures/PhoneDrop/   files, .thumbs/ .clip/ .partial/ .notes.json .hashes.json
                            ~/.config/phonedrop/    sessions.json, ca.pem/ca-key.pem (root), cert.pem/key.pem (leaf)
```

## Trust model

| Who | How they get in | What they can do |
|---|---|---|
| **This PC** (loopback) | one-time code baked into the URL the browser is opened with | everything, including device management, guest links, clipboard, "open folder" |
| **Paired device** | scans the QR (per-run secret, valid `--pair-minutes` after start), then the PC approves it | browse, upload, download, delete files and notes |
| **Pending device** | scanned the QR, not yet approved | poll its own approval status only |
| **Guest** | opens a one-time guest link made on the PC | upload only, for `--guest-minutes`, sees only what it sent |
| **Anyone else on the LAN** | – | the locked page, the public root certificate |

Rules that hold everywhere:

- The session cookie is `HttpOnly`, `SameSite=Lax`, `Secure` on TLS. Session IDs are random
  256-bit values stored **hashed** in `sessions.json`; the file never contains anything that could be
  replayed.
- Every state-changing request needs the `X-PhoneDrop: 1` header and, when present, a same-origin
  `Origin`. Requests with an unknown `Host` are refused (DNS rebinding).
- "Local only" endpoints check that the TCP peer is loopback **and** owned by the same Unix user
  (`peer_uid()` via `/proc/net/tcp`; loopback alone where that file doesn't exist), not a header.
  Another account's loopback request to `/pair` or `/g` gets 403 before the lockout counts it.
- Each listener accepts at most 64 connections (16 per IP); 20 s socket timeout until the headers
  are in, 60 s for the body. At most 3 pending pairing requests per IP, 10 in total.
- Received files are 0600 in a 0700 folder. JPEG/PNG/WebP that fail to strip are rejected (415);
  ImageMagick inputs are pinned to the sniffed coder (`JPEG:file[0]`), ffmpeg gets
  `-protocol_whitelist file`, PDF previews prefer `pdftoppm`. Pairing/guest queries are logged
  as `?<redacted>`, control characters escaped.
- Pairing secrets live in memory for one run. Nothing in a photographed QR or a browser history
  works after a restart.
- File types are decided from content; only images, audio/video and PDF are ever served inline, and
  always under a sandboxing CSP. Everything else is a download.

## Sessions (`sessions.json`)

```json
{ "<sha256 of session id>": {
    "id": "k3Jd8Qp2",            public handle used by the device panel
    "role": "device" | "guest",
    "status": "pending" | "active",
    "name": "iPhone · Safari",   derived from the User-Agent at pairing
    "ip": "…", "created": <epoch>, "last_seen": <epoch>, "expires": <epoch> } }
```

- `valid_session()` requires `status == "active"` and not expired. Pending sessions only reach
  `/api/pair-status`. Guests only reach `/api/upload` and `/api/info`.
- `last_seen` is updated in memory on every authenticated request and flushed to disk at most once
  a minute.
- The PC's own session is created already `active` (it authenticated with the loopback code).

## Pairing flow with approval

```
phone  GET /pair?t=<secret>      ─► session {pending}, cookie, 303 → /
phone  GET /                     ─► pending.html (polls /api/pair-status every 2 s)
PC     long-poll /api/files      ◄─ response carries pending: [{id, name, ip}]  → banner "Allow …?"
PC     POST /api/devices/<id>/approve | /deny      (loopback only)
phone  /api/pair-status → {status: "active"}       → reload → full panel
```

`--no-confirm` skips approval (old behaviour). A desktop notification (`notify-send`, if present)
is shown when a device asks to pair and when a guest link is used.

## Guest drop links

`POST /api/guest` (loopback) creates an in-memory one-time token valid for 10 minutes (any older
link stops working) and returns `{url, expires, qr}`; the panel shows the URL as text and `qr` as an
image (a `data:image/png` URL from `qrencode`, or `null` if it isn't installed). `DELETE /api/guest`
revokes the link. Visiting `/g?t=<token>` goes through the pairing brute-force limiter, consumes the
token and creates a `guest` session valid for `--guest-minutes` (default 30); a browser that is
already a paired device keeps its session and leaves the token unused. Guests get `guest.html` +
`guest.js` (app.js is never loaded): upload buttons, a progress list, the names they sent, nothing
else. After the auth gate a guest can reach only `GET /api/info` (`{guest, name, maxBytes,
expires}`) and `POST /api/upload`; everything else is 403. Guest uploads are saved with a `guest-`
prefix and logged with the guest's name. Guests appear in the device panel and can be revoked like
any device; once the session ends, the page's next request gets 401 and it says so.

## Certificates

A private root CA is generated once (`ca.pem` / `ca-key.pem`, mode 0600, ECDSA P-256, 10 years) with
critical name constraints (private/CGNAT/link-local/loopback IPs, `.local`, `localhost`) and
used to sign a short-lived **leaf** certificate for the current LAN IPs. When the IP changes, only
the leaf is re-issued; a phone that trusted the root keeps verifying TLS properly. A LAN IP outside
the constrained ranges is left out of the leaf (with a warning). `cert.json` records `"ca": 2`; an
older root (other value, or no Name Constraints) is regenerated along with the leaf and a notice is
printed. The server sends `chain.pem` (leaf + root, rewritten whenever either changes). `GET /ca.crt`
serves the root certificate (public information) so phones can install it; the locked and pending
pages link to it with per-platform instructions. The terminal prints the **root** fingerprint first (the
one to compare: iOS/Android show it in their certificate installer), then the leaf's.

## Hashes

`Hasher` is a background thread (same shape as `Clipper`): a queue fed by uploads and a startup scan,
one file at a time, results in `.hashes.json` keyed by file name with the `mtime_ns` they were
computed for. `/api/files` carries `sha256` (or `null` while pending); the viewer shows it with
click-to-copy.

## Front end

`static/app.js` is plain ES2020. State is a few module-level variables (`files`, `notes`, `info`,
`selected`), re-rendered from the long-poll response (`/api/files?wait=<version>`) which returns
within 25 s or as soon as anything changes: a file, a note, a conversion step, a pending device,
a hash. `version` is a string that concatenates per-subsystem counters, so any change wakes every
connected panel.

## Testing

No test framework is required. The pattern that works: import `phonedrop` as a module in a tiny
harness (so the in-memory pairing secret can be read), drive the API with `curl`, and load the real
pages in a headless Chromium-based browser over the DevTools protocol to catch console errors and
take screenshots at desktop and phone widths.
