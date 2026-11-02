# PhoneDrop

Send photos, videos, files and text between your phone and your computer over Wi-Fi. No cloud,
no accounts, no pip installs: just Python 3 and `openssl`. Optional extras: `qrencode` (QR codes),
`vipsthumbnail` or ImageMagick (fast previews, HEIC support), `ffmpeg` (video previews and video
metadata stripping), `wl-copy` (clipboard on Wayland), `notify-send` (desktop notifications).

```bash
git clone https://github.com/ThatRaccoonGuy/PhoneDrop.git
cd PhoneDrop
python3 phonedrop.py
```

### Pair a phone

1. A QR code appears in the terminal and the panel opens in your browser.
2. Within 10 minutes, scan the QR with your phone (same Wi-Fi). The phone warns about the
   certificate the first time; compare the root SHA-256 fingerprint printed in the terminal if
   you want to be sure, and continue.
3. The phone now waits for approval. The panel on the computer shows "iPhone · Safari (…) wants to
   pair" (and a desktop notification, if `notify-send` is installed): click **Allow**. Paired
   devices stay paired for 30 days; to pair another one later, restart PhoneDrop.

Optional, once per phone: open **Trust this computer** on the pairing page and install the root
certificate as the page explains (iPhone: install the profile, then enable it under Settings →
General → About → Certificate Trust Settings; Android: Settings → Security → Encryption &
credentials → Install a certificate → CA certificate). The warning is then gone for good, even
when the computer's IP address changes.

### Use it

- **Phone → computer**: tap **Send photos & videos**, or **Send files** for PDFs, documents and
  archives. They appear live on the computer, saved to `~/Pictures/PhoneDrop`. Videos and audio
  play right in the panel.
- **Computer → phone**: drag files onto the panel or press Ctrl+V; on the phone, **Share** opens
  the share sheet (iPhone: "Save Image" / "Save Video") or hands the file to any app.
- **On the computer**: **Copy** puts an image on the clipboard as PNG (photos are converted in the
  background as they arrive, with a progress bar), **Save** downloads, **Download all** gives a zip,
  **Select** picks several files to zip or delete together. The viewer shows each file's SHA-256;
  click it to copy the digest.
- **Text and links**: paste into the box on either device and it appears on the other with
  **Copy** and **Open**. On the computer, Ctrl+V anywhere on the page sends the clipboard text.
- **Devices** (header, computer only) lists every paired device and lets you revoke them one by
  one, or all at once with **Revoke all devices** (this computer stays paired).
- **Guest link** (header, computer only) lets someone who isn't paired send you files: click
  **Create link** and let them scan the QR (or send them the link). It works once, within
  10 minutes, and gives a page that can only upload, for 30 minutes (`--guest-minutes`). Their
  files are saved with a `guest-` prefix and they show up under **Devices**, where you can revoke
  them early.

If you run a firewall, allow the phone port from your local network only. For example, with UFW
(replace `192.168.0.0/24` with your network's range):

```bash
sudo ufw allow from 192.168.0.0/24 to any port 8443 proto tcp
```

## Options

| Flag | Default | |
|---|---|---|
| `--port` | 8443 | HTTPS port for the phone |
| `--local-port` | 8080 | localhost-only HTTP port for this PC |
| `--bind` | LAN address | interface for the phone port (`0.0.0.0` = all interfaces) |
| `--pair-minutes` | 10 | how long after startup new devices can pair (`0` = no limit) |
| `--dir` | `~/Pictures/PhoneDrop` | where received files are saved |
| `--max-mb` | 2048 | per-file size limit |
| `--clip-cache` | 30 | keep ready-to-paste PNGs for this many recent images (~17 MB each) |
| `--keep-metadata` | | don't strip EXIF/XMP metadata from received images |
| `--keep-days` | 0 | delete received files and notes after this many days (0 = keep forever) |
| `--guest-minutes` | 30 | how long someone who opened a guest link can upload |
| `--no-confirm` | | pair devices without approval on the PC |
| `--new-token` | | unpairs every device |
| `--no-browser` | | don't auto-open the panel |

## Security

- **Pairing required**: a 256-bit secret in the QR code, new on every run, never saved to disk, and
  only accepted for 10 minutes after startup. An old QR code or a pairing link left in browser
  history is useless. The PC's browser pairs with a separate one-time code that only works from
  this computer, as the user running PhoneDrop, and expires 2 minutes after startup. Pairing sets
  a 30-day HttpOnly session cookie; session IDs are stored hashed in `~/.config/phonedrop/`
  (mode 0700).
- **Approval on the PC**: scanning the QR alone isn't enough. A new device only gets a "waiting
  for approval" page until you click **Allow** in the panel on this computer; requests nobody
  approves expire after 15 minutes, and at most 3 per IP (10 in total) can wait at once. The
  **Devices** dialog (this computer only) shows every paired device with its IP and when it was
  last seen, and **Revoke** cuts one off immediately.
- **LAN only by default**: the phone port listens on your LAN address, not on every interface
  (VPNs, Docker networks, public IPs). PhoneDrop warns you if that address isn't a private one.
- **Encrypted on the LAN**: TLS 1.2+ with an auto-generated ECDSA certificate. The PC uses plain HTTP,
  but only on 127.0.0.1.
- **Connection limits**: at most 64 open connections per port and 16 per client IP; a client that
  stays silent for 20 s before its request is complete (60 s while sending a body) is disconnected.
- **Guest links are single use and upload-only**: a random 192-bit token, kept in memory only, valid
  for 10 minutes and used up by the first visit (making a new link or clicking **Revoke link**
  cancels the old one). A guest can only upload; it can't list, download or delete anything, read
  the shared text, or see where files are stored. Its session ends after `--guest-minutes`, or as
  soon as you revoke it under **Devices**. Links can only be made from this computer.
- **Private root certificate**: on first run PhoneDrop creates its own root CA (10 years) and uses
  it to sign a short-lived certificate for the computer's current LAN addresses; when the address
  changes, only that certificate is re-issued. The root's private key (`ca-key.pem`, mode 0600)
  never leaves `~/.config/phonedrop/`; only the public root certificate is offered at `/ca.crt`.
  Trusting it on a phone means: whoever holds `ca-key.pem` can impersonate this computer to that
  phone. Nothing else: the root carries critical name constraints, so it can only vouch for private,
  CGNAT, link-local and loopback IPs, `*.local` and `localhost`, never for a public site. Roots made
  by older versions (without constraints) are replaced on start; reinstall the new one on the phone. If
  you think the key was copied, delete `ca.pem` and `ca-key.pem` (a new root is made on the next
  start) and remove the old profile/certificate from the phone.
- **Brute-force lockout**: 8 bad pairing or guest-link attempts per IP → 15-minute block.
- **CSRF / DNS rebinding**: changes need a custom header plus a matching Origin, and requests with
  an unknown `Host` header are rejected.
- **Upload validation**: the type is checked from the file's content, not its name. Accepted:
  images (JPEG, PNG, GIF, WebP, HEIC, AVIF, BMP, TIFF), video (MP4, MOV, WebM, MKV, 3GP), audio
  (MP3, M4A, OGG, WAV, FLAC), PDF, archives (ZIP, 7z, gz, tar), office/e-book documents and plain
  text. SVG, HTML, executables and anything else are rejected. Only images, audio/video and PDFs
  are ever shown inline; every other file is served as a download, never rendered. Names are
  sanitized, files are written atomically with mode 0600 into a 0700 folder and never overwrite
  each other, and there are checks for size and free disk space (counting uploads in progress).
- **Metadata stripped on arrival**: phone photos carry GPS coordinates, the phone model and serial
  numbers, and often a hidden trailer (embedded "motion photo" video, depth map). PhoneDrop removes
  all of that from JPEG, PNG and WebP files without re-encoding them (pixels stay identical, only
  the orientation tag is kept). MP4/MOV videos are remuxed with `ffmpeg` to drop their location
  and device tags (streams are copied, not re-encoded). A JPEG/PNG/WebP that can't be parsed is
  rejected rather than stored with its metadata. HEIC/AVIF/TIFF/WebM/MKV are stored as-is; the
  terminal log and the upload list say "metadata kept".
  Use `--keep-metadata` to turn this off.
- **Hardened responses**: strict CSP, no framing, `nosniff`, no referrer; images, media and PDFs
  are the only things ever rendered inline, and they are served under a sandboxing CSP.
- Clipboard copy, "Open folder" and device management work only from this computer.

### Know this before you use it

- **Use it on networks you trust** (home Wi-Fi, a phone hotspot). Until the phone trusts PhoneDrop's
  root certificate, the first connection can't be verified automatically. On public or shared Wi-Fi,
  an attacker could intercept that first visit and steal the pairing secret. Comparing the root
  SHA-256 fingerprint printed in the terminal with the one your phone's certificate installer
  shows rules this out, and once the root is installed every later connection is verified.
- **A paired device has full access**: it can see, download, upload and delete every file in the
  PhoneDrop folder and every shared note. Only pair your own devices, and don't show the QR code to anyone (or in a
  screenshot or stream) while the pairing window is open, and only approve requests you expect.
  Revoke a lost device under **Devices**, or run with `--new-token` to unpair everything.
  Guests (people you sent a guest link) are different: they can only upload, and only for a while.
- **Files are processed by ImageMagick / libvips / ffmpeg / poppler** (previews, clipboard conversion,
  video remuxing). Bugs in media decoders have been exploited before, so keep them updated. PhoneDrop
  limits the damage: images whose header declares more than 80 megapixels are never decoded,
  ImageMagick runs with hard memory/time limits, and if `bwrap` (bubblewrap) is installed and
  usable on your kernel, every decoder runs in a sandbox with no network, no home directory and a
  read-only input. PhoneDrop tests the sandbox at startup and the startup text says whether it is
  active. Only paired devices and guests
  you sent a link to can upload.
- **Don't expose it to the internet**: no port forwarding, and don't use `--bind 0.0.0.0` on a
  machine with a public IP. It's built for a local network.
- **The PC side is plain HTTP on 127.0.0.1**, which never leaves your computer. "This computer"
  means the same Unix user: connections from other accounts are refused as local (checked via
  `/proc/net/tcp`), so they can't pair with the PC's code or use PC-only features, and still need a
  paired session like any device.
- **Paired sessions last 30 days** and aren't tied to the device's IP. Anyone who copies the
  session cookie out of a paired browser gets the same access.

## Security patch notes

Two review rounds have been run against PhoneDrop so far: an independent code review (2026-11-01)
and a red-team exercise with two attackers (2026-11-02) who tried to get in as an unpaired host on
the Wi-Fi, a malicious web page, a guest, a revoked or still-pending phone, and another local user
account. What they found, and what changed:

**Red-team round (2026-11-02)**

- *Medium* — A tiny PNG declaring 30000×30000 pixels made ImageMagick allocate ~7 GB when it was
  used as the preview/clipboard fallback; reachable through a guest upload. **Fixed:** pixel budget
  read from the file header before any decoder runs, ImageMagick resource limits, bubblewrap sandbox
  around every decoder.
- *Medium* — Video remuxing ran inside the upload request with a 10-minute ceiling, so a burst of
  slow video uploads could pin the worker threads. **Fixed:** 120 s limit, at most two remuxes at a
  time, 503 when busy.
- *Low* — A `Range` header with thousands of digits crashed that request with a traceback.
  **Fixed:** bounded parsing.
- *Low* — The TLS certificate advertised the computer's hostname to anyone on the network.
  **Fixed:** removed from the certificate; existing installs re-issue it automatically, phones keep
  their trust.
- *Hardening* — An absolute 20-second deadline for request headers (slow-header connections),
  larger global cap on pending pairing requests.
- *Review of the fixes* found two more: a sandbox that is installed but unusable would have failed
  silently (now probed at startup, with an honest fallback), and lossless WebP escaped the pixel
  budget (now parsed). Both fixed.
- *Accepted* — Commit timestamps carry the author's UTC offset; a paired device remains trusted
  within its connection caps.

The detailed working notes (reproductions, memory figures, per-fix verification) were kept out of
the repository on purpose; this section is the record.

Tried and held: unauthenticated access to any file or API, path traversal variants, cookie forgery
and reuse after revoke, guest/pending escalation, CSRF with and without `Origin`, DNS rebinding,
script injection through notes, file names and device names, clickjacking, Range edge cases,
long-poll floods. The git history contains no personal data.

**Code review round (2026-11-01)**

- *High* — The PC's session cookie could be captured by another local account listening on a
  loopback port and replayed. **Fixed:** the PC side now requires the same Unix user.
- *Medium* — Terminal escape injection via the request log; unbounded connection threads; memory
  blow-ups on malformed images; root certificate without name constraints; leaf-only chain.
  **All fixed** (see the Security section above).
- *Low* — Pinned decoders, 0600 files, pending-request caps, redacted logs, disk reservation for
  parallel uploads, expiring one-time PC code.

## License

[MIT](LICENSE) © 2026 ThatRaccoonGuy
