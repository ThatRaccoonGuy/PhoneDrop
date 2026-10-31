# PhoneDrop

Send photos from your phone to your computer over Wi-Fi. No cloud, no accounts, no pip installs:
just Python 3 and `openssl`. Optional extras: `qrencode` (QR code in the terminal), `vipsthumbnail` or
ImageMagick (fast gallery previews, HEIC support), `wl-copy` (clipboard on Wayland).

```bash
git clone https://github.com/ThatRaccoonGuy/PhoneDrop.git
cd PhoneDrop
python3 phonedrop.py
```

1. A QR code appears in the terminal and the panel opens in your browser.
2. Scan the QR with your phone (same Wi-Fi). Accept the self-signed certificate warning once
   (compare the SHA-256 fingerprint printed in the terminal if you want to be sure).
3. Tap **Send photos**. Images show up live on the computer, saved to `~/Pictures/PhoneDrop`.
4. On the computer: **Copy** puts the image on the clipboard as PNG (each photo is converted in the
   background as it arrives, with a progress bar; Copy unlocks when it's ready), **Save** downloads it,
   **Download all** gives a zip. You can also drag-and-drop or Ctrl+V images into the PC
   panel to get them onto your phone.

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
| `--dir` | `~/Pictures/PhoneDrop` | where images are saved |
| `--max-mb` | 200 | per-file size limit |
| `--clip-cache` | 30 | keep ready-to-paste PNGs for this many recent images (~17 MB each) |
| `--new-token` | | new QR code, unpairs every device |
| `--no-browser` | | don't auto-open the panel |

## Security

- **Pairing required**: a 256-bit secret in the QR code. Scanning it sets a 30-day HttpOnly session
  cookie, and the token is removed from the URL straight away. Session IDs are stored hashed in
  `~/.config/phonedrop/` (mode 0700).
- **Encrypted on the LAN**: TLS 1.2+ with an auto-generated ECDSA certificate. The PC uses plain HTTP,
  but only on 127.0.0.1.
- **Brute-force lockout**: 8 bad pairing attempts per IP → 15-minute block.
- **CSRF / DNS rebinding**: changes need a custom header plus a matching Origin, and requests with
  an unknown `Host` header are rejected.
- **Upload validation**: the type is checked from the file's magic bytes (JPEG, PNG, GIF, WebP,
  HEIC, AVIF, BMP, TIFF). SVG and other files are rejected. Names are sanitized, files are written
  atomically and never overwrite each other, and there are checks for size and free disk space.
- **Hardened responses**: strict CSP, no framing, `nosniff`, no referrer, and image files are served sandboxed.
- Clipboard copy and "Open folder" work only from this computer.

## License

[MIT](LICENSE) © 2026 ThatRaccoonGuy
