# PhoneDrop

Send photos, videos and files from your phone to your computer over Wi-Fi. No cloud, no accounts, no pip installs:
just Python 3 and `openssl`. Optional extras: `qrencode` (QR code in the terminal), `vipsthumbnail` or
ImageMagick (fast gallery previews, HEIC support), `ffmpeg` (video previews and video metadata
stripping), `wl-copy` (clipboard on Wayland).

```bash
git clone https://github.com/ThatRaccoonGuy/PhoneDrop.git
cd PhoneDrop
python3 phonedrop.py
```

1. A QR code appears in the terminal and the panel opens in your browser.
2. Within 10 minutes, scan the QR with your phone (same Wi-Fi). Accept the certificate warning
   (compare the root SHA-256 fingerprint printed in the terminal if you want to be sure). Optional,
   once per phone: open **Trust this computer** on the pairing page, download the root certificate
   and install it as the page explains (iPhone: install the profile, then enable it under
   Settings → General → About → Certificate Trust Settings; Android: Settings → Security →
   Encryption & credentials → Install a certificate → CA certificate). After that the warning is
   gone for good, even when the computer's IP address changes.
   The phone then waits for approval: the panel on the computer shows "iPhone · Safari (…) wants
   to pair" (plus a desktop notification if `notify-send` is installed); click **Allow**.
   Paired devices stay paired for 30 days; to pair a new one later, restart PhoneDrop. **Devices**
   in the panel's header lists every paired device and lets you revoke them one by one.
3. Tap **Send photos & videos** (or **Send files** for PDFs, documents, archives…). They show up
   live on the computer, saved to `~/Pictures/PhoneDrop`. Videos and audio play in the panel.
   Going the other way, **Share** on the phone opens its share sheet, where you can save to the
   camera roll ("Save Image" / "Save Video" on iPhone) or pass the file to any app.
4. On the computer: **Copy** puts the image on the clipboard as PNG (each photo is converted in the
   background as it arrives, with a progress bar; Copy unlocks when it's ready), **Save** downloads it,
   **Download all** gives a zip, and **Select** lets you pick several files to zip or delete together. You can also drag-and-drop or Ctrl+V images into the PC
   panel to get them onto your phone. The viewer shows each file's SHA-256 (click it to copy the full
   digest) so you can check a transfer against the original.
5. **Text and links** work the same way: paste a link or some text into the box on either device
   and it shows up on the other one with **Copy** and **Open** buttons. On the computer, pressing
   Ctrl+V anywhere on the page sends whatever text is on the clipboard.
6. **Guest links** let someone who isn't paired send you files (a friend's photos, say) without
   pairing their phone. Click **Guest link** in the panel's header, then **Create link**, and let
   them scan the QR code (or send them the link). The link works once, within 10 minutes; whoever
   opens it gets a page that can only upload, for 30 minutes (`--guest-minutes`). Their files are
   saved with a `guest-` prefix, and they show up under **Devices**, where you can revoke them early.

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
| `--dir` | `~/Pictures/PhoneDrop` | where images are saved |
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
  this computer. Pairing sets a 30-day HttpOnly session cookie; session IDs are stored hashed in
  `~/.config/phonedrop/` (mode 0700).
- **Approval on the PC**: scanning the QR alone isn't enough. A new device only gets a "waiting
  for approval" page until you click **Allow** in the panel on this computer; requests nobody
  approves expire after 15 minutes. The **Devices** dialog (this computer only) shows every paired
  device with its IP and when it was last seen, and **Revoke** cuts one off immediately.
- **LAN only by default**: the phone port listens on your LAN address, not on every interface
  (VPNs, Docker networks, public IPs). PhoneDrop warns you if that address isn't a private one.
- **Encrypted on the LAN**: TLS 1.2+ with an auto-generated ECDSA certificate. The PC uses plain HTTP,
  but only on 127.0.0.1.
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
  phone. Nothing else — it's a private root that only ever signs PhoneDrop's own certificate. If
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
  sanitized, files are written atomically and never overwrite each other, and there are checks for
  size and free disk space.
- **Metadata stripped on arrival**: phone photos carry GPS coordinates, the phone model and serial
  numbers, and often a hidden trailer (embedded "motion photo" video, depth map). PhoneDrop removes
  all of that from JPEG, PNG and WebP files without re-encoding them (pixels stay identical, only
  the orientation tag is kept). MP4/MOV videos are remuxed with `ffmpeg` to drop their location
  and device tags (streams are copied, not re-encoded). HEIC/AVIF/TIFF/WebM/MKV are stored as-is;
  the terminal log says which.
  Use `--keep-metadata` to turn this off.
- **Hardened responses**: strict CSP, no framing, `nosniff`, no referrer, and image files are served sandboxed.
- Clipboard copy, "Open folder" and device management work only from this computer.

### Know this before you use it

- **Use it on networks you trust** (home Wi-Fi, a phone hotspot). Until the phone trusts PhoneDrop's
  root certificate, the first connection can't be verified automatically. On public or shared Wi-Fi,
  an attacker could intercept that first visit and steal the pairing secret. Comparing the root
  SHA-256 fingerprint printed in the terminal with the one your phone's certificate installer
  shows rules this out, and once the root is installed every later connection is verified.
- **A paired device has full access**: it can see, download, upload and delete every image in the
  PhoneDrop folder. Only pair your own devices, and don't show the QR code to anyone (or in a
  screenshot or stream) while the pairing window is open, and only approve requests you expect.
  Revoke a lost device under **Devices**, or run with `--new-token` to unpair everything.
  Guests (people you sent a guest link) are different: they can only upload, and only for a while.
- **Images are processed by ImageMagick / libvips** (previews and clipboard conversion). Bugs in
  image decoders have been exploited before, so keep them updated. Only paired devices and guests
  you sent a link to can upload.
- **Don't expose it to the internet**: no port forwarding, and don't use `--bind 0.0.0.0` on a
  machine with a public IP. It's built for a local network.
- **The PC side is plain HTTP on 127.0.0.1**, which never leaves your computer. Other user accounts
  on the same computer can reach the port, but they still need a paired session.
- **Paired sessions last 30 days** and aren't tied to the device's IP. Anyone who copies the
  session cookie out of a paired browser gets the same access.

## License

[MIT](LICENSE) © 2026 ThatRaccoonGuy
