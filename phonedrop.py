#!/usr/bin/env python3
"""PhoneDrop — send photos, videos and files from your phone to this computer over the local network.

Two listeners:
  * HTTPS on the LAN (default :8443) for the phone (certificate signed by a private root CA made on
    first run; phones can install the root from /ca.crt to stop the warning)
  * HTTP on 127.0.0.1 (default :8080) for this computer's browser (localhost is a secure
    context, so clipboard copy works without certificate warnings)

Access requires pairing: scan the QR code printed in the terminal, then click Allow in the panel on
this computer (--no-confirm skips that). The pairing secret is new on every run and only works for
a few minutes after startup. Pairing sets a long-lived HttpOnly session cookie. Paired devices can
be revoked one by one from the panel's Devices dialog, or all at once with --new-token.

Guest links let someone who isn't paired send files once: a single-use link (valid 10 minutes)
opens an upload-only session for --guest-minutes.
"""
import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import select
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.parse
import zipfile
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "phonedrop"

SESSION_COOKIE = "pd_session"
SESSION_TTL = 30 * 24 * 3600
LONG_POLL_SECONDS = 25
PAIR_MAX_FAILS = 8
PAIR_FAIL_WINDOW = 15 * 60
PAIR_MINUTES = 10
PENDING_TTL = 15 * 60  # a pairing request nobody approves is dropped after this long
LAST_SEEN_FLUSH = 60  # write last_seen times to disk at most this often
GUEST_LINK_TTL = 10 * 60  # an unused guest link stops working after this long
GUEST_MINUTES = 30
LOCAL_CODE_TTL = 120  # the PC's one-time pairing code (opened in its browser) stops working after this long
PENDING_MAX_PER_IP = 3  # pairing requests waiting for approval, per IP and in total
PENDING_MAX = 20
MAX_PIXELS = 80_000_000  # images above this (e.g. a 30000x30000 "bomb") get no preview or clipboard copy
VIDEO_STRIP_TIMEOUT = 120  # seconds ffmpeg may spend remuxing one upload (it runs in the request thread)
VIDEO_SLOTS = threading.BoundedSemaphore(2)  # concurrent ffmpeg remuxes; more wait, then get 503
MAX_CONNECTIONS = 64  # open connections per listener; more are closed at once
MAX_CONNECTIONS_PER_IP = 16  # browsers open about 6 per host, so this only stops floods
HEADER_TIMEOUT = 20  # seconds a client may stay silent before its request headers are complete
KEEPALIVE_IDLE = 75  # seconds a kept-alive connection may sit idle between requests (browsers pre-open sockets)
BODY_TIMEOUT = 60  # seconds a client may stay silent while sending a body
DISK_RESERVE = 256 * 1024 * 1024  # free space always left on the disk

IMAGE_MIME = {
    "jpg": "image/jpeg", "png": "image/png", "gif": "image/gif", "webp": "image/webp",
    "heic": "image/heic", "avif": "image/avif", "bmp": "image/bmp", "tiff": "image/tiff",
}
VIDEO_MIME = {"mp4": "video/mp4", "m4v": "video/mp4", "mov": "video/quicktime", "webm": "video/webm",
              "mkv": "video/x-matroska", "3gp": "video/3gpp"}
AUDIO_MIME = {"mp3": "audio/mpeg", "m4a": "audio/mp4", "ogg": "audio/ogg", "wav": "audio/wav", "flac": "audio/flac"}
# Everything else is only ever served as a download, never rendered by the browser.
FILE_EXTS = {"pdf", "zip", "7z", "gz", "tar", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub",
             "txt", "md", "csv", "json", "log", "srt", "ics", "vcf"}
ZIP_BASED = {"docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "zip"}
TEXT_EXTS = {"txt", "md", "csv", "json", "log", "srt", "ics", "vcf"}
MIME = {**IMAGE_MIME, **VIDEO_MIME, **AUDIO_MIME, "pdf": "application/pdf",
        **{e: "application/octet-stream" for e in FILE_EXTS if e != "pdf"}}
SNIFF_BYTES = 1024
# ImageMagick picks a decoder from the file's content unless told otherwise; pinning it to the type we
# sniffed keeps a file from reaching coders (MVG, MSL, SVG, PS…) that were never meant to see uploads.
CODER = {"jpg": "JPEG", "png": "PNG", "gif": "GIF", "webp": "WEBP", "heic": "HEIC", "avif": "AVIF",
         "bmp": "BMP", "tiff": "TIFF", "pdf": "PDF"}


def kind_of(ext: str) -> str:
    if ext in IMAGE_MIME:
        return "image"
    if ext in VIDEO_MIME:
        return "video"
    if ext in AUDIO_MIME:
        return "audio"
    return "pdf" if ext == "pdf" else "file"
STATIC_FILES = {
    "app.js": "text/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
    "icon.svg": "image/svg+xml",
    "pending.js": "text/javascript; charset=utf-8",
    "guest.js": "text/javascript; charset=utf-8",
}
CLIP_KEEP = 30  # PNG clipboard copies kept for this many most-recently-used images
THUMB_SIZES = (480, 1600)  # grid, and the viewer for formats browsers can't display (HEIC/TIFF)
NOTE_MAX_CHARS = 20000
CLEANUP_INTERVAL = 15 * 60
NOTE_KEEP = 200
GENERIC_STEMS = {"image", "photo", "img", "file", "blob", "picture", "upload"}

PAGE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; media-src 'self'; "
            "connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
FILE_CSP = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; sandbox"


def sniff_image(head: bytes):
    """Return the image extension based on magic bytes, or None. SVG is deliberately rejected."""
    if head.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head[4:8] == b"ftyp":
        brands = head[8:64]
        if b"avif" in brands or b"avis" in brands:
            return "avif"
        if any(b in brands for b in (b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"mif1", b"msf1")):
            return "heic"
    if (head.startswith(b"BM") and len(head) >= 26
            and int.from_bytes(head[14:18], "little") in (12, 40, 52, 56, 108, 124)):  # known DIB headers
        return "bmp"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    return None


def sniff_type(head: bytes, claimed_ext: str):
    """Work out the real type of an upload from its first bytes. The extension the phone sent is
    only trusted to tell apart formats that share a container (docx vs zip) or plain-text files."""
    ext = sniff_image(head)
    if ext:
        return ext
    if head[4:8] == b"ftyp":
        major, brands = head[8:12], head[8:64]
        if major == b"qt  ":
            return "mov"
        if major == b"M4A ":
            return "m4a"
        if major.startswith(b"3g"):
            return "3gp"
        if any(b in brands for b in (b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"M4V ", b"mp71", b"iso5", b"iso6")):
            return "mp4"
        return None
    if head.startswith(b"\x1a\x45\xdf\xa3"):
        return "webm" if b"webm" in head[:64] else "mkv"
    if head.startswith(b"ID3") or (head[0:1] == b"\xff" and head[1:2] in (b"\xfb", b"\xf3", b"\xf2", b"\xe3")):
        return "mp3"
    if head.startswith(b"OggS"):
        return "ogg"
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "wav"
    if head.startswith(b"fLaC"):
        return "flac"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        return claimed_ext if claimed_ext in ZIP_BASED else "zip"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gz"
    if head[257:262] == b"ustar":
        return "tar"
    if claimed_ext in TEXT_EXTS and b"\0" not in head:
        try:
            head.decode("utf-8")
        except UnicodeDecodeError:
            try:
                head[:-3].decode("utf-8")  # a multi-byte character may be cut at the buffer edge
            except UnicodeDecodeError:
                return None
        return claimed_ext
    return None


def claimed_extension(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


# ---------------------------------------------------------------- running decoders on untrusted files
#
# vips, ImageMagick, ffmpeg and poppler all parse attacker-controlled bytes. Every call goes through
# media_cmd(): ImageMagick gets hard resource limits, and when bubblewrap is installed the decoder runs
# in a throwaway namespace with no network, no home directory, the input read-only and only its output
# directory writable. A bug in a decoder then yields a sandboxed process, not the user's files.

MAGICK_LIMITS = {"MAGICK_AREA_LIMIT": "128MP", "MAGICK_MEMORY_LIMIT": "1GiB", "MAGICK_MAP_LIMIT": "2GiB",
                 "MAGICK_DISK_LIMIT": "2GiB", "MAGICK_WIDTH_LIMIT": "20000", "MAGICK_HEIGHT_LIMIT": "20000",
                 "MAGICK_TIME_LIMIT": "120"}
SANDBOX = shutil.which("bwrap")


def media_cmd(cmd: list, inputs: list, outdir: Path) -> list:
    """Wrap a decoder command for media_env()/subprocess: sandboxed with bwrap when available."""
    if not SANDBOX:
        return cmd
    wrap = [SANDBOX, "--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc", "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--unshare-all", "--die-with-parent",
            "--new-session", "--clearenv", "--setenv", "PATH", "/usr/bin", "--setenv", "HOME", "/tmp"]
    for k, v in MAGICK_LIMITS.items():
        wrap += ["--setenv", k, v]
    for i in inputs:
        wrap += ["--ro-bind", str(i), str(i)]
    wrap += ["--bind", str(outdir), str(outdir), "--"]
    return wrap + cmd


def probe_sandbox():
    """bwrap can be installed yet unusable (unprivileged user namespaces disabled). Try it once, and
    fall back to unsandboxed decoders with the ImageMagick limits rather than failing every decode —
    which would also silently leave video metadata in place."""
    global SANDBOX
    if not SANDBOX:
        return
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)  # bwrap needs the bound directory to exist
        ok = subprocess.run(media_cmd(["/usr/bin/true"], [], CONFIG_DIR), capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        ok = False
    if not ok:
        SANDBOX = None


def media_env() -> dict:
    """Environment for decoders run without bwrap: at least the ImageMagick limits apply."""
    return {**os.environ, **MAGICK_LIMITS}


def image_pixels(path: Path, ext: str):
    """Width*height from the file header for the formats that declare it cheaply, else None.
    Lets us refuse to decode a tiny file that would expand to gigabytes of pixels."""
    try:
        with open(path, "rb") as f:
            head = f.read(32)
            if ext == "png" and head[12:16] == b"IHDR":
                return int.from_bytes(head[16:20], "big") * int.from_bytes(head[20:24], "big")
            if ext == "gif":
                return int.from_bytes(head[6:8], "little") * int.from_bytes(head[8:10], "little")
            if ext == "bmp":
                return abs(int.from_bytes(head[18:22], "little", signed=True)) * abs(int.from_bytes(head[22:26], "little", signed=True))
            if ext == "webp" and head[12:16] == b"VP8X":
                return (1 + int.from_bytes(head[24:27], "little")) * (1 + int.from_bytes(head[27:30], "little"))
            if ext == "webp" and head[12:16] == b"VP8 ":
                return (int.from_bytes(head[26:28], "little") & 0x3FFF) * (int.from_bytes(head[28:30], "little") & 0x3FFF)
            if ext == "webp" and head[12:16] == b"VP8L":  # lossless: 14-bit width-1 and height-1 after the signature byte
                bits = int.from_bytes(head[21:25], "little")
                return ((bits & 0x3FFF) + 1) * (((bits >> 14) & 0x3FFF) + 1)
            if ext == "jpg":
                f.seek(2)
                while True:
                    marker = f.read(2)
                    if len(marker) < 2 or marker[0] != 0xFF:
                        return None
                    if marker[1] in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                        sof = f.read(7)
                        return int.from_bytes(sof[3:5], "big") * int.from_bytes(sof[5:7], "big")
                    if marker[1] == 0xDA:
                        return None
                    length = int.from_bytes(f.read(2), "big")
                    if length < 2:
                        return None
                    f.seek(length - 2, 1)
    except (OSError, IndexError, ValueError):
        return None
    return None


def too_many_pixels(path: Path, ext: str) -> bool:
    px = image_pixels(path, ext)
    return px is not None and px > MAX_PIXELS


def strip_video(path: Path, ext: str) -> bool:
    """Remux the video without its global metadata (GPS, device). Streams are copied, not re-encoded."""
    if ext not in ("mp4", "m4v", "mov", "3gp") or not shutil.which("ffmpeg"):
        return False
    fmt = {"mov": "mov", "3gp": "3gp"}.get(ext, "mp4")
    outdir = path.parent / f".remux-{secrets.token_hex(6)}"  # only this directory is writable inside the sandbox
    outdir.mkdir(mode=0o700)
    tmp = outdir / "out"
    try:
        cmd = ["ffmpeg", "-v", "error", "-y", "-protocol_whitelist", "file", "-i", str(path), "-map", "0",
               "-map_metadata", "-1", "-c", "copy", "-movflags", "+faststart", "-f", fmt, str(tmp)]
        r = subprocess.run(media_cmd(cmd, [path], outdir), capture_output=True, timeout=VIDEO_STRIP_TIMEOUT,
                           env=media_env())
        if r.returncode or not tmp.exists() or not tmp.stat().st_size:
            return False
        os.replace(tmp, path)
        return True
    except subprocess.TimeoutExpired:
        return False
    finally:
        shutil.rmtree(outdir, ignore_errors=True)


# ---------------------------------------------------------------- metadata stripping
#
# Phone photos carry EXIF/XMP blocks with GPS coordinates, the phone model, serial numbers, and
# sometimes an embedded video or depth map after the image. These functions remove that without
# re-encoding the pixels, so there is zero quality loss. Only the EXIF orientation is kept, because
# without it photos would show up rotated.

JPEG_KEEP = {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF,  # SOF*/DHT
             0xDB, 0xDD, 0xE0, 0xEE}  # DQT, DRI, APP0 (JFIF), APP14 (Adobe colour transform)
STRIPPABLE = {"jpg", "png", "webp"}


def exif_orientation(app1: bytes):
    """Orientation (1-8) from an Exif APP1 payload, or None."""
    try:
        if not app1.startswith(b"Exif\0\0"):
            return None
        t = app1[6:]
        end = "<" if t[:2] == b"II" else ">" if t[:2] == b"MM" else None
        if not end:
            return None
        ifd = int.from_bytes(t[4:8], "little" if end == "<" else "big")
        n = int.from_bytes(t[ifd:ifd + 2], "little" if end == "<" else "big")
        for i in range(n):
            e = t[ifd + 2 + 12 * i: ifd + 14 + 12 * i]
            tag = int.from_bytes(e[0:2], "little" if end == "<" else "big")
            if tag == 0x0112:
                v = int.from_bytes(e[8:10], "little" if end == "<" else "big")
                return v if 1 <= v <= 8 else None
    except (IndexError, ValueError):
        pass
    return None


def minimal_exif(orientation: int) -> bytes:
    """An APP1 segment whose only tag is Orientation."""
    tiff = b"II*\0" + (8).to_bytes(4, "little") + (1).to_bytes(2, "little")
    tiff += (0x0112).to_bytes(2, "little") + (3).to_bytes(2, "little") + (1).to_bytes(4, "little")
    tiff += orientation.to_bytes(2, "little") + b"\0\0" + b"\0\0\0\0"
    payload = b"Exif\0\0" + tiff
    return b"\xff\xe1" + (len(payload) + 2).to_bytes(2, "big") + payload


def _copy_until(src, dst, end_marker: bytes, chunk=1024 * 1024):
    """Copy src to dst up to and including end_marker; anything after it is dropped."""
    carry = b""
    while True:
        buf = src.read(chunk)
        if not buf:
            dst.write(carry)
            return
        data = carry + buf
        i = data.find(end_marker)
        if i >= 0:
            dst.write(data[:i + len(end_marker)])
            return
        dst.write(data[:-1])
        carry = data[-1:]


def _copy_exact(src, dst, n: int, chunk=1024 * 1024):
    """Copy exactly n bytes from src to dst, in pieces."""
    while n > 0:
        buf = src.read(min(n, chunk))
        if not buf:
            raise ValueError("truncated")
        dst.write(buf)
        n -= len(buf)


def _skip_fill(src, chunk=64 * 1024) -> int:
    """Skip a run of 0xFF fill bytes in bulk; returns the marker byte that follows it."""
    while True:
        buf = src.read(chunk)
        if not buf:
            raise ValueError("truncated")
        rest = buf.lstrip(b"\xff")
        if rest:
            src.seek(1 - len(rest), 1)  # leave the file just after the marker byte
            return rest[0]


def strip_jpeg(src, dst):
    size = os.fstat(src.fileno()).st_size
    if src.read(2) != b"\xff\xd8":
        raise ValueError("not a JPEG")
    dst.write(b"\xff\xd8")
    orientation = None
    while True:
        marker = src.read(2)
        if len(marker) < 2 or marker[0] != 0xFF:
            raise ValueError("bad segment")
        kind = marker[1]
        if kind == 0xFF:
            kind = _skip_fill(src)
            marker = bytes((0xFF, kind))
        if kind == 0xDA:  # start of scan: write orientation, then copy the image data up to EOI
            if orientation and orientation != 1:
                dst.write(minimal_exif(orientation))
            dst.write(marker)
            _copy_until(src, dst, b"\xff\xd9")
            return
        raw = src.read(2)
        length = int.from_bytes(raw, "big")
        if len(raw) < 2 or length < 2:
            raise ValueError("bad segment length")
        if length - 2 > size - src.tell():  # never allocate more than the file can hold
            raise ValueError("segment runs past the end of the file")
        payload = src.read(length - 2)
        if len(payload) != length - 2:
            raise ValueError("truncated segment")
        if kind == 0xE1 and orientation is None:
            orientation = exif_orientation(payload)
        keep = kind in JPEG_KEEP or (kind == 0xE2 and payload.startswith(b"ICC_PROFILE\0"))
        if keep:
            dst.write(marker + length.to_bytes(2, "big") + payload)


PNG_DROP = {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"}


def strip_png(src, dst):
    size = os.fstat(src.fileno()).st_size
    sig = src.read(8)
    if sig != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    dst.write(sig)
    while True:
        head = src.read(8)
        if len(head) < 8:
            raise ValueError("truncated")
        length = int.from_bytes(head[:4], "big")
        if length > 2 ** 31 - 1 or length + 4 > size - src.tell():
            raise ValueError("chunk runs past the end of the file")
        kind = head[4:]
        body = src.read(length + 4)
        if len(body) != length + 4:
            raise ValueError("truncated chunk")
        if kind not in PNG_DROP:
            dst.write(head + body)
        if kind == b"IEND":
            return


def strip_webp(src, dst):
    """Chunks are streamed through; the RIFF size is patched in at the end."""
    file_size = os.fstat(src.fileno()).st_size
    head = src.read(12)
    if head[:4] != b"RIFF" or head[8:] != b"WEBP":
        raise ValueError("not a WebP")
    dst.write(b"RIFF\0\0\0\0WEBP")
    total = 4
    while True:
        h = src.read(8)
        if len(h) < 8:
            break
        size = int.from_bytes(h[4:], "little")
        left = file_size - src.tell()
        if size > left:
            raise ValueError("truncated chunk")
        n = min(size + (size & 1), left)  # the pad byte may be missing at the very end
        if h[:4] in (b"EXIF", b"XMP "):
            src.seek(n, 1)
            continue
        dst.write(h)
        if h[:4] == b"VP8X":
            if size < 1:
                raise ValueError("bad VP8X chunk")
            dst.write(bytes([src.read(1)[0] & ~0x0C]))  # clear the EXIF and XMP flags
            _copy_exact(src, dst, n - 1)
        else:
            _copy_exact(src, dst, n)
        total += 8 + n
    if total > 0xFFFFFFFF:
        raise ValueError("too large for RIFF")
    dst.seek(4)
    dst.write(total.to_bytes(4, "little"))


def strip_metadata(path: Path, ext: str) -> bool:
    """Rewrite the file without metadata. Returns False (file untouched) if the format isn't
    supported or the file couldn't be parsed."""
    fn = {"jpg": strip_jpeg, "png": strip_png, "webp": strip_webp}.get(ext)
    if not fn:
        return False
    tmp = path.with_name(path.name + ".strip")
    try:
        with open(path, "rb") as src, open(tmp, "wb") as dst:
            fn(src, dst)
        os.replace(tmp, path)
        return True
    except Exception:  # a malformed file must never take the request down with it
        tmp.unlink(missing_ok=True)
        return False


def safe_stem(name: str, kind: str = "image") -> str:
    name = unicodedata.normalize("NFKC", name).replace("\\", "/").rsplit("/", 1)[-1]
    stem = name.rsplit(".", 1)[0] if "." in name else name
    stem = re.sub(r"[^\w\- ()]+", "_", stem, flags=re.UNICODE).strip(" ._-")[:80]
    if not stem or stem.lower() in GENERIC_STEMS:
        prefix = {"image": "IMG", "video": "VID", "audio": "AUD"}.get(kind, "FILE")
        stem = time.strftime(f"{prefix}_%Y%m%d_%H%M%S")
    return stem


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def lan_ips():
    ips = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))  # no packet is sent; just picks the outgoing interface
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    return sorted(ip for ip in ips if not ipaddress.ip_address(ip).is_loopback)


def device_name(ua: str) -> str:
    """A short label like "iPhone · Safari" for the device panel and pairing prompts."""
    device = next((label for needle, label in (
        ("iPad", "iPad"), ("iPhone", "iPhone"), ("Android", "Android"), ("CrOS", "ChromeOS"),
        ("Macintosh", "Mac"), ("Windows", "Windows"), ("Linux", "Linux")) if needle in ua), None)
    # Order matters: Edge and Brave also say Chrome, and Chrome also says Safari.
    browser = next((label for needles, label in (
        (("Edg/", "EdgA/", "EdgiOS/"), "Edge"), (("Brave",), "Brave"), (("Firefox/", "FxiOS/"), "Firefox"),
        (("Chrome/", "CriOS/", "Chromium/"), "Chrome"), (("Safari/",), "Safari"))
        if any(n in ua for n in needles)), None)
    return " · ".join(x for x in (device, browser) if x) or "Unknown device"


def primary_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


# ---------------------------------------------------------------- state

class State:
    def __init__(self, store: Path, max_bytes: int, new_token: bool, pair_minutes: int, keep_metadata=False,
                 keep_days=0, no_confirm=False, guest_minutes=GUEST_MINUTES):
        self.store = store
        self.no_confirm = no_confirm
        self.guest_minutes = guest_minutes
        # Guest drop links: token -> expiry. In memory only and single use, like the pairing secret.
        self.guest_tokens = {}
        self.keep_metadata = keep_metadata
        self.keep_days = keep_days
        self.partial = store / ".partial"
        self.thumbs = store / ".thumbs"
        self.thumb_locks = {}
        self.thumb_slots = threading.BoundedSemaphore(2)  # cap concurrent decoders
        self.max_bytes = max_bytes
        self.clipper = None
        self.hasher = None
        self.notes_file = store / ".notes.json"
        self.notes_tick = 0
        try:
            self.notes = [n for n in json.loads(self.notes_file.read_text())
                          if isinstance(n, dict) and isinstance(n.get("text"), str)]
        except (OSError, ValueError):
            self.notes = []
        self.lock = threading.Lock()
        self.fails = {}  # ip -> [count, first_ts]
        self.inflight = 0  # bytes of uploads in progress, so parallel uploads can't overfill the disk
        CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(CONFIG_DIR, 0o700)
        store.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(store, 0o700)
        self.partial.mkdir(exist_ok=True, mode=0o700)
        self.thumbs.mkdir(exist_ok=True, mode=0o700)
        for leftover in self.partial.iterdir():
            leftover.unlink(missing_ok=True)
        self.prune_thumbs()

        self.sessions_file = CONFIG_DIR / "sessions.json"
        (CONFIG_DIR / "token").unlink(missing_ok=True)  # older versions kept a permanent pairing token here
        if new_token:
            self._write_private(self.sessions_file, "{}")
        # Pairing secrets are fresh every run and never written to disk, so a QR code someone
        # photographed or a pairing URL left in browser history stops working after a restart.
        self.token = secrets.token_urlsafe(32)
        self.pair_until = time.time() + pair_minutes * 60 if pair_minutes > 0 else None
        # One-time, loopback-only code for auto-opening this PC's browser, so the phone token
        # doesn't end up in the desktop browser's history.
        self.local_code = secrets.token_urlsafe(32)
        self.local_until = time.time() + LOCAL_CODE_TTL
        self.sessions_tick = 0  # bumped on every add/approve/deny/revoke, wakes the PC's long-poll
        self.sessions_saved = 0.0
        self.sessions_dirty = False  # last_seen changed since the last write
        try:
            raw = json.loads(self.sessions_file.read_text())
        except (OSError, ValueError):
            raw = {}
        now = time.time()
        self.sessions = {}
        migrated = False
        for k, v in (raw.items() if isinstance(raw, dict) else ()):
            if not isinstance(v, dict) or not isinstance(v.get("expires"), (int, float)) or v["expires"] <= now:
                migrated = True
                continue
            if "id" not in v:
                v, migrated = self._migrate(v, now), True
            self.sessions[k] = v
        if migrated:
            with self.lock:
                self._save_sessions()

    @staticmethod
    def _migrate(old: dict, now: float) -> dict:
        """Older versions stored only expires/ip/ua and a "created" date string."""
        try:
            created = time.mktime(time.strptime(old.get("created", ""), "%Y-%m-%d %H:%M:%S"))
        except (TypeError, ValueError, OverflowError):
            created = now
        return {"id": secrets.token_urlsafe(6), "role": "device", "status": "active",
                "name": device_name(old.get("ua", "")), "ip": old.get("ip", ""), "created": created,
                "last_seen": now, "expires": old["expires"]}

    @staticmethod
    def _write_private(path: Path, text: str):
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)

    # Session ids are stored hashed, so a leaked sessions.json can't be replayed.
    @staticmethod
    def _h(sid: str) -> str:
        return hashlib.sha256(sid.encode()).hexdigest()

    # ---- sessions (paired devices)

    def _save_sessions(self, structural=True):
        """Write sessions.json. Call with self.lock held."""
        self._write_private(self.sessions_file, json.dumps(self.sessions, indent=1))
        self.sessions_saved, self.sessions_dirty = time.time(), False
        if structural:
            self.sessions_tick += 1

    def new_session(self, ip: str, ua: str, status="active", role="device", ttl=None) -> tuple:
        """Returns (sid, record), or (None, None) if too many pairing requests are already waiting."""
        sid = secrets.token_urlsafe(32)
        now = time.time()
        if ttl is None:
            ttl = SESSION_TTL if status == "active" else PENDING_TTL
        rec = {"id": secrets.token_urlsafe(6), "role": role, "status": status, "name": device_name(ua),
               "ip": ip, "created": now, "last_seen": now, "expires": now + ttl}
        with self.lock:
            if status == "pending":
                waiting = [v["ip"] for v in self.sessions.values() if v["status"] == "pending" and v["expires"] > now]
                if len(waiting) >= PENDING_MAX or waiting.count(ip) >= PENDING_MAX_PER_IP:
                    return None, None
            self.sessions[self._h(sid)] = rec
            self._save_sessions()
        return sid, rec

    def session_for(self, sid: str):
        """The session record for a cookie, whatever its status, or None."""
        if not sid:
            return None
        s = self.sessions.get(self._h(sid))
        return s if s and s["expires"] > time.time() else None

    def valid_session(self, sid: str) -> bool:
        s = self.session_for(sid)
        return bool(s and s.get("status") == "active")

    def touch_session(self, sid: str):
        """Note that the session was just used. Written to disk at most once a minute."""
        s = self.session_for(sid)
        if not s:
            return
        s["last_seen"] = time.time()
        self.sessions_dirty = True
        if time.time() - self.sessions_saved >= LAST_SEEN_FLUSH:
            self.flush_sessions()

    def flush_sessions(self):
        with self.lock:
            if self.sessions_dirty:
                self._save_sessions(structural=False)

    def prune_sessions(self):
        """Drop expired sessions, including pairing requests nobody approved."""
        now = time.time()
        with self.lock:
            dead = [k for k, v in self.sessions.items() if v["expires"] <= now]
            for k in dead:
                del self.sessions[k]
            if dead:
                self._save_sessions()

    def sessions_forever(self):
        while True:
            time.sleep(LAST_SEEN_FLUSH)
            try:
                self.prune_sessions()
                self.flush_sessions()
            except Exception as e:  # keep the sweeper alive
                sys.stderr.write(f"session sweep failed: {e}\n")

    def drop_session(self, sid: str):
        with self.lock:
            if self.sessions.pop(self._h(sid), None) is not None:
                self._save_sessions()

    def _key_for(self, did: str):
        return next((k for k, v in self.sessions.items() if v["id"] == did), None)

    def approve_device(self, did: str):
        """Let a pending device in. Returns its record, or None if there is no such request."""
        with self.lock:
            k = self._key_for(did)
            if not k or self.sessions[k]["status"] != "pending" or self.sessions[k]["expires"] <= time.time():
                return None
            rec = self.sessions[k]
            rec.update(status="active", expires=time.time() + SESSION_TTL)
            self._save_sessions()
        return rec

    def remove_device(self, did: str):
        """Deny a pairing request or revoke a paired device. Returns the removed record or None."""
        with self.lock:
            k = self._key_for(did)
            if not k:
                return None
            rec = self.sessions.pop(k)
            self._save_sessions()
        return rec

    def remove_all_devices(self, keep_sid: str) -> int:
        """Revoke every device, guest and pending request except the session `keep_sid` (this
        computer's own, so the panel doesn't lock itself out). Unused guest links die with them."""
        keep = self._h(keep_sid) if keep_sid else None
        with self.lock:
            gone = [k for k in self.sessions if k != keep]
            for k in gone:
                del self.sessions[k]
            self.guest_tokens = {}
            if gone:
                self._save_sessions()
        return len(gone)

    def pending_devices(self):
        self.prune_sessions()
        with self.lock:  # the sweeper thread may delete entries while we iterate
            recs = sorted(self.sessions.values(), key=lambda v: v["created"])
        return [{k: v[k] for k in ("id", "name", "ip", "created")} for v in recs if v["status"] == "pending"]

    def devices(self, current_sid: str):
        self.prune_sessions()
        me = self._h(current_sid) if current_sid else None
        with self.lock:
            items = list(self.sessions.items())
        out = [{**{k: v.get(k) for k in ("id", "name", "ip", "created", "last_seen", "expires", "role", "status")},
                "current": k == me} for k, v in items]
        out.sort(key=lambda d: d["created"], reverse=True)
        return out

    def pair_blocked(self, ip: str) -> bool:
        with self.lock:
            rec = self.fails.get(ip)
            if rec and time.time() - rec[1] > PAIR_FAIL_WINDOW:
                del self.fails[ip]
                return False
            return bool(rec and rec[0] >= PAIR_MAX_FAILS)

    def pair_failed(self, ip: str):
        with self.lock:
            rec = self.fails.setdefault(ip, [0, time.time()])
            rec[0] += 1

    def pair_succeeded(self, ip: str):
        with self.lock:
            self.fails.pop(ip, None)

    def pairing_open(self) -> bool:
        return self.pair_until is None or time.time() < self.pair_until

    def check_token(self, t: str, local: bool):
        """Which secret the pairing link carried: "local" (this PC's one-time code), "phone", or None."""
        t = t.encode()
        with self.lock:
            if (local and self.local_code and time.time() < self.local_until
                    and hmac.compare_digest(t, self.local_code.encode())):
                self.local_code = None
                return "local"
        return "phone" if self.pairing_open() and hmac.compare_digest(t, self.token.encode()) else None

    # ---- guest drop links (one-time, upload-only access for someone who isn't paired)

    def create_guest_token(self) -> tuple:
        """A new single-use guest link token and its expiry. Any older, unused link stops working."""
        token = secrets.token_urlsafe(24)
        expires = time.time() + GUEST_LINK_TTL
        with self.lock:
            self.guest_tokens = {token: expires}
        return token, expires

    def consume_guest_token(self, t: str) -> bool:
        """True if t is a live guest token, which is then used up. Expired tokens are dropped on the way."""
        t = t.encode()
        now = time.time()
        with self.lock:
            for k, exp in list(self.guest_tokens.items()):
                if exp <= now:
                    del self.guest_tokens[k]
                elif hmac.compare_digest(t, k.encode()):
                    del self.guest_tokens[k]
                    return True
        return False

    def revoke_guest_tokens(self) -> int:
        with self.lock:
            n, self.guest_tokens = len(self.guest_tokens), {}
        return n

    # ---- files

    def version(self) -> str:
        tick = self.clipper.tick if self.clipper else 0
        hashes = self.hasher.tick if self.hasher else 0
        return f"{self.store.stat().st_mtime_ns}.{tick}.{self.notes_tick}.{self.sessions_tick}.{hashes}"

    # ---- notes (text and links shared between devices)

    def add_note(self, text: str) -> dict:
        note = {"id": secrets.token_urlsafe(8), "text": text, "time": time.time()}
        with self.lock:
            self.notes.append(note)
            del self.notes[:-NOTE_KEEP]
            self._save_notes()
        return note

    def find_note(self, nid: str):
        return next((n for n in self.notes if n["id"] == nid), None)

    def delete_note(self, nid: str) -> bool:
        with self.lock:
            before = len(self.notes)
            self.notes = [n for n in self.notes if n["id"] != nid]
            if len(self.notes) == before:
                return False
            self._save_notes()
        return True

    def _save_notes(self):
        self._write_private(self.notes_file, json.dumps(self.notes))
        self.notes_tick += 1

    def resolve(self, name: str):
        """Map a client-supplied file name to a path inside the store, or None."""
        if not name or name.startswith(".") or "/" in name or "\\" in name or "\x00" in name:
            return None
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext not in MIME:
            return None
        p = self.store / name
        try:
            if p.resolve().parent != self.store.resolve() or not p.is_file():
                return None
        except OSError:
            return None
        return p

    def remove_file(self, name: str) -> bool:
        p = self.resolve(name)
        if not p:
            return False
        p.unlink()
        self.drop_thumbs(name)
        if self.clipper:
            self.clipper.forget(name)
        if self.hasher:
            self.hasher.forget(name)
        return True

    # ---- automatic cleanup

    def cleanup(self):
        """Delete files and notes older than --keep-days. Returns (files, notes) removed."""
        if not self.keep_days:
            return 0, 0
        cutoff = time.time() - self.keep_days * 86400
        old = [f["name"] for f in self.listing() if f["mtime"] < cutoff]
        removed = sum(self.remove_file(n) for n in old)
        with self.lock:
            before = len(self.notes)
            self.notes = [n for n in self.notes if n.get("time", 0) >= cutoff]
            dropped = before - len(self.notes)
            if dropped:
                self._save_notes()
        return removed, dropped

    def cleanup_forever(self):
        while True:
            try:
                files, notes = self.cleanup()
                if files or notes:
                    sys.stderr.write(f"{time.strftime('%H:%M:%S')} cleanup: removed {files} file(s) and "
                                     f"{notes} note(s) older than {self.keep_days} day(s)\n")
            except Exception as e:  # keep the sweeper alive
                sys.stderr.write(f"cleanup failed: {e}\n")
            time.sleep(CLEANUP_INTERVAL)

    # ---- thumbnails (cached JPEGs, so the gallery doesn't pull full-size photos over Wi-Fi)

    def thumb_path(self, p: Path, size: int) -> Path:
        key = hashlib.sha256(p.name.encode()).hexdigest()[:20]
        return self.thumbs / f"{key}-{size}-{p.stat().st_mtime_ns}.jpg"

    def thumbnail(self, p: Path, size: int):
        out = self.thumb_path(p, size)
        if out.exists():
            return out
        with self.lock:
            lock = self.thumb_locks.setdefault(out.name, threading.Lock())
        with lock, self.thumb_slots:
            if out.exists():
                return out
            tmp = self.thumbs / f".{secrets.token_hex(6)}.jpg"
            cmds = []
            ext = p.suffix[1:].lower()
            kind = kind_of(ext)
            if kind == "image" and too_many_pixels(p, ext):
                return None  # a "decompression bomb": store it, but never decode it
            if kind == "video" and shutil.which("ffmpeg"):
                # A frame from one second in (or the first frame for very short clips).
                for ss in ("1", "0"):
                    cmds.append(["ffmpeg", "-v", "error", "-y", "-protocol_whitelist", "file", "-ss", ss, "-i", str(p),
                                 "-frames:v", "1",
                                 "-vf", f"scale='min({size},iw)':-2", "-q:v", "4", "-f", "image2", str(tmp)])
            elif kind == "pdf":
                if shutil.which("pdftoppm"):  # poppler only reads PDF; it writes <prefix>.jpg, i.e. tmp
                    cmds.append(["pdftoppm", "-f", "1", "-l", "1", "-scale-to", str(size), "-jpeg", "-singlefile",
                                 str(p), str(tmp.with_suffix(""))])
                if shutil.which("magick"):
                    cmds.append(["magick", "-density", "72", f"{CODER[ext]}:{p}[0]", "-background", "white",
                                 "-alpha", "remove", "-thumbnail", f"{size}x{size}>", "-quality", "78", "-strip",
                                 f"jpg:{tmp}"])
            elif kind == "image":
                if shutil.which("vipsthumbnail"):
                    cmds.append(["vipsthumbnail", str(p), "-s", f"{size}x{size}", "-o", f"{tmp}[Q=78,strip]"])
                if shutil.which("magick"):
                    cmds.append(["magick", f"{CODER[ext]}:{p}[0]", "-auto-orient", "-thumbnail", f"{size}x{size}>",
                                 "-quality", "78", "-strip", f"jpg:{tmp}"])
            try:
                for cmd in cmds:
                    try:
                        r = subprocess.run(media_cmd(cmd, [p], self.thumbs), capture_output=True, timeout=60,
                                           env=media_env())
                    except subprocess.TimeoutExpired:
                        continue
                    if r.returncode == 0 and tmp.exists() and tmp.stat().st_size:
                        os.replace(tmp, out)
                        return out
                return None
            finally:
                tmp.unlink(missing_ok=True)
                with self.lock:
                    self.thumb_locks.pop(out.name, None)

    def drop_thumbs(self, name: str):
        key = hashlib.sha256(name.encode()).hexdigest()[:20]
        for t in self.thumbs.glob(f"{key}-*.jpg"):
            t.unlink(missing_ok=True)

    def prune_thumbs(self):
        keep = set()
        for p in self.store.iterdir():
            if p.is_file() and not p.name.startswith("."):
                for size in THUMB_SIZES:
                    keep.add(self.thumb_path(p, size).name)
        for t in self.thumbs.iterdir():
            if t.name not in keep:
                t.unlink(missing_ok=True)

    def listing(self):
        files = []
        for p in self.store.iterdir():
            if p.name.startswith(".") or not p.is_file():
                continue
            ext = p.suffix[1:].lower()
            if ext not in MIME:
                continue
            st = p.stat()
            q = urllib.parse.quote(p.name)
            kind = kind_of(ext)
            f = {"name": p.name, "size": st.st_size, "mtime": st.st_mtime, "type": MIME[ext], "kind": kind,
                 "url": f"/f/{q}?v={st.st_mtime_ns}", "thumb": f"/t/{q}?v={st.st_mtime_ns}"}
            if self.clipper and kind == "image":
                f["clip"], f["clipPct"] = self.clipper.status(p)
            f["sha256"] = self.hasher.status(p) if self.hasher else None
            files.append(f)
        files.sort(key=lambda f: f["mtime"], reverse=True)
        return files


# ---------------------------------------------------------------- clipboard PNGs

class Clipper:
    """Converts images to PNG in the background so Copy is instant.

    Most apps only accept image/png when pasting, and converting a 12 MP photo on demand takes
    seconds. Conversion runs one image at a time, newest first, and reports progress so the panel
    can show it. PNGs are kept for the `keep` most recently used images (least recently used evicted).
    """

    def __init__(self, state: State, keep: int):
        self.state = state
        self.dir = state.store / ".clip"
        self.dir.mkdir(exist_ok=True, mode=0o700)
        self.keep = keep
        self.cv = threading.Condition()
        self.queue = deque()
        self.current = None  # name being converted
        self.pct = 0
        self.failed = set()  # cache file names that failed to convert
        self.tick = 0  # bumped on every visible status change
        for t in self.dir.glob(".*"):
            t.unlink(missing_ok=True)
        threading.Thread(target=self.run, daemon=True).start()

    def path(self, p: Path) -> Path:
        key = hashlib.sha256(p.name.encode()).hexdigest()[:20]
        return self.dir / f"{key}-{p.stat().st_mtime_ns}.png"

    def ready_source(self, p: Path):
        """The file to put on the clipboard, or None if it isn't converted yet."""
        if p.suffix.lower() == ".png":
            return p
        out = self.path(p)
        return out if out.exists() else None

    def status(self, p: Path):
        if self.ready_source(p):
            return "ready", 100
        with self.cv:
            if self.current == p.name:
                return "converting", self.pct
            if p.name in self.queue:
                return "queued", 0
        return ("error" if self.path(p).name in self.failed else "none"), 0

    def bump(self):
        self.tick += 1

    def request(self, name: str, front=False):
        with self.cv:
            if name == self.current:
                return
            if name in self.queue:
                if not front:
                    return
                self.queue.remove(name)
            self.queue.appendleft(name) if front else self.queue.append(name)
            self.bump()
            self.cv.notify()

    def forget(self, name: str):
        key = hashlib.sha256(name.encode()).hexdigest()[:20]
        with self.cv:
            if name in self.queue:
                self.queue.remove(name)
        for t in self.dir.glob(f"{key}-*.png"):
            t.unlink(missing_ok=True)

    def scan(self):
        """Drop PNGs of deleted/changed images, and queue the newest images that lack one."""
        files = [self.state.resolve(f["name"]) for f in self.state.listing() if f["kind"] == "image"]
        files = [p for p in files if p]
        valid = {self.path(p).name for p in files}
        for t in self.dir.glob("*.png"):
            if t.name not in valid:
                t.unlink(missing_ok=True)
        self.evict()
        for p in files[:self.keep]:
            if not self.ready_source(p):
                self.request(p.name)

    def touch(self, png: Path):
        if png.parent == self.dir:
            os.utime(png)

    def evict(self):
        pngs = sorted(self.dir.glob("*.png"), key=lambda t: t.stat().st_mtime, reverse=True)
        for t in pngs[self.keep:]:
            t.unlink(missing_ok=True)

    def run(self):
        while True:
            with self.cv:
                while not self.queue:
                    self.cv.wait()
                name = self.queue.popleft()
                self.current, self.pct = name, 0
                self.bump()
            try:
                p = self.state.resolve(name)
                if p and kind_of(p.suffix[1:].lower()) == "image" and not self.ready_source(p):
                    out = self.path(p)
                    if self.convert(p, out):
                        self.failed.discard(out.name)
                        self.evict()
                    else:
                        self.failed.add(out.name)
            except Exception as e:  # never let the worker thread die
                sys.stderr.write(f"clipboard conversion of {name} failed: {e}\n")
            finally:
                with self.cv:
                    self.current = None
                    self.bump()

    def convert(self, src: Path, out: Path) -> bool:
        tmp = self.dir / f".{secrets.token_hex(6)}.png"
        if too_many_pixels(src, src.suffix[1:].lower()):
            return False  # never decode a "decompression bomb"
        try:
            if shutil.which("vips") and self._vips(src, tmp):
                pass
            elif shutil.which("magick"):
                cmd = ["magick", f"{CODER[src.suffix[1:].lower()]}:{src}[0]", "-auto-orient", "-define",
                       "png:compression-level=1", f"png:{tmp}"]
                r = subprocess.run(media_cmd(cmd, [src], self.dir), capture_output=True, timeout=180, env=media_env())
                if r.returncode:
                    return False
            else:
                return False
            if not tmp.exists() or not tmp.stat().st_size:
                return False
            os.replace(tmp, out)
            return True
        except subprocess.TimeoutExpired:
            return False
        finally:
            tmp.unlink(missing_ok=True)

    def _vips(self, src: Path, tmp: Path) -> bool:
        # --vips-progress reports two phases: decoding the source (fast), then encoding the PNG.
        cmd = ["vips", "--vips-progress", "autorot", str(src), f"{tmp}[compression=1]"]
        proc = subprocess.Popen(media_cmd(cmd, [src], self.dir), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=media_env())
        deadline = time.time() + 180
        buf = b""
        try:
            while True:
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                buf += chunk
                *lines, buf = re.split(rb"[\r\n]", buf)
                for line in lines:
                    m = re.match(rb"vips (.+): (\d+)% complete", line.strip())
                    if not m:
                        continue
                    pct = int(m.group(2))
                    pct = 10 + pct * 0.9 if m.group(1).startswith(b"temp-") else pct * 0.1
                    if int(pct) >= self.pct + 3 or pct >= 100:
                        self.pct = min(99, int(pct))
                        self.bump()
                if time.time() > deadline:
                    proc.kill()
                    return False
            return proc.wait(timeout=10) == 0
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


# ---------------------------------------------------------------- SHA-256 per file

class Hasher:
    """Computes the SHA-256 of every file in the background, so a copy made from here can be verified
    later. (It is the digest of the stored file; images and videos usually differ from the phone's
    original because their metadata was stripped on arrival.)

    One file at a time, newest first. Digests are cached in .hashes.json with the mtime_ns they
    were computed for, so a restart only hashes files that are new or changed.
    """

    def __init__(self, state: State):
        self.state = state
        self.file = state.store / ".hashes.json"
        self.cv = threading.Condition()
        self.queue = deque()
        self.current = None  # name being hashed
        self.tick = 0  # bumped whenever a digest becomes available
        try:
            raw = json.loads(self.file.read_text())
        except (OSError, ValueError):
            raw = {}
        self.hashes = {k: v for k, v in (raw.items() if isinstance(raw, dict) else ())
                       if isinstance(v, dict) and isinstance(v.get("mtime_ns"), int)
                       and isinstance(v.get("sha256"), str)}
        threading.Thread(target=self.run, daemon=True).start()

    def status(self, p: Path):
        """The hex digest, or None while it's pending."""
        try:
            mtime = p.stat().st_mtime_ns
        except OSError:
            return None
        with self.cv:
            h = self.hashes.get(p.name)
        return h["sha256"] if h and h["mtime_ns"] == mtime else None

    def _save(self):
        """Write .hashes.json. Call with self.cv held."""
        State._write_private(self.file, json.dumps(self.hashes))

    def request(self, name: str):
        with self.cv:
            if name == self.current or name in self.queue:
                return
            self.queue.append(name)
            self.cv.notify()

    def forget(self, name: str):
        with self.cv:
            if name in self.queue:
                self.queue.remove(name)
            if self.hashes.pop(name, None):
                self._save()

    def scan(self):
        """Drop digests of deleted/changed files, and queue every file that lacks one."""
        files = [p for p in (self.state.resolve(f["name"]) for f in self.state.listing()) if p]
        mtimes = {p.name: p.stat().st_mtime_ns for p in files}
        with self.cv:
            stale = [k for k, v in self.hashes.items() if mtimes.get(k) != v["mtime_ns"]]
            for k in stale:
                del self.hashes[k]
            if stale:
                self._save()
        for p in files:  # listing() is newest first
            if p.name not in self.hashes:
                self.request(p.name)

    def run(self):
        while True:
            with self.cv:
                while not self.queue:
                    self.cv.wait()
                name = self.queue.popleft()
                self.current = name
            try:
                p = self.state.resolve(name)
                if p and not self.status(p):
                    mtime = p.stat().st_mtime_ns
                    h = hashlib.sha256()
                    with open(p, "rb") as f:
                        while chunk := f.read(1024 * 1024):
                            h.update(chunk)
                    with self.cv:
                        # Skip if the file was deleted or replaced while it was being read.
                        if self.state.resolve(name) and p.stat().st_mtime_ns == mtime:
                            self.hashes[name] = {"mtime_ns": mtime, "sha256": h.hexdigest()}
                            self._save()
                            self.tick += 1
            except Exception as e:  # never let the worker thread die
                sys.stderr.write(f"hashing {name} failed: {e}\n")
            finally:
                with self.cv:
                    self.current = None


# ---------------------------------------------------------------- HTTP

# Control characters in a request line (e.g. an ESC sequence) must not reach the terminal as-is.
CONTROL_CHARS = getattr(BaseHTTPRequestHandler, "_control_char_table", None) or str.maketrans(
    {c: f"\\x{c:02x}" for c in (*range(0x20), *range(0x7F, 0xA0))})
TCP_TABLES = ("/proc/net/tcp", "/proc/net/tcp6")


def tcp_owner(table: str, local_port: int, remote_port: int, local_ip: str = None):
    """The uid owning the socket in a /proc/net/tcp listing whose local end is local_ip:local_port and
    remote port remote_port, or None. Rows are "sl local rem st queues timer retr uid …", addresses are
    hex addr:port (IPv4 addresses little-endian, e.g. 127.0.0.1 is 0100007F). The address is matched
    too, so 127.0.0.2:<port> can't be confused with 127.0.0.1:<port>."""
    want_ip = socket.inet_aton(local_ip)[::-1].hex().upper() if local_ip else None
    for line in table.splitlines()[1:]:
        f = line.split()
        if len(f) < 8 or f[3] == "06":  # TIME_WAIT rows no longer belong to anyone
            continue
        try:
            addr, port = f[1].rsplit(":", 1)
            if int(port, 16) != local_port or int(f[2].rsplit(":", 1)[1], 16) != remote_port:
                continue
            if want_ip and len(addr) == 8 and addr.upper() != want_ip:
                continue
            return int(f[7])
        except (IndexError, ValueError):
            continue
    return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "PhoneDrop"
    sys_version = ""
    timeout = HEADER_TIMEOUT  # per-socket-op timeout; raised to BODY_TIMEOUT once the headers are in
    # Send each response as a single write with Nagle off. Otherwise headers and body go out as separate
    # small packets and TCP delayed-ACK adds ~40 ms (much more on a phone's Wi-Fi) to every request.
    disable_nagle_algorithm = True
    wbufsize = 64 * 1024

    state: State = None
    allowed_hosts: set = set()
    local_port = 8080  # for the "approve it in the panel" hint
    phone_base = ""  # https://<LAN IP>:<port>, for guest links
    ca_der = b""  # root certificate (DER), served at /ca.crt
    check_uid = True  # False where /proc/net/tcp doesn't exist: loopback alone then counts as local

    # ---- helpers

    @property
    def is_tls(self):
        return isinstance(self.connection, ssl.SSLSocket)

    @property
    def is_loopback(self):
        return ipaddress.ip_address(self.client_address[0]).is_loopback

    @property
    def is_local(self):
        """This computer, as the same Unix user that runs PhoneDrop. Loopback alone isn't enough:
        cookies aren't port-scoped, so another account could catch our cookie on a port of its own
        and replay it from 127.0.0.1."""
        if not hasattr(self, "_local"):
            self._local = self.is_loopback and (not self.check_uid or self.peer_uid() == os.getuid())
        return self._local

    def peer_uid(self):
        """The uid owning the client end of this TCP connection (from /proc/net/tcp), or None."""
        for name in TCP_TABLES:
            try:
                with open(name) as f:
                    uid = tcp_owner(f.read(), self.client_address[1], self.server.server_address[1],
                                    self.client_address[0])
            except OSError:
                continue
            if uid is not None:
                return uid
        return None

    def log_message(self, fmt, *args):
        msg = fmt % args
        # Pairing and guest links carry their secret in the query, whatever the parameter is called.
        msg = re.sub(r'((?:^|[\s"]|://[^/\s"]*)/(?:pair|g)[^\s?"]*)\?[^\s"]*', r"\1?<redacted>", msg)
        msg = re.sub(r"([?&]t=)[^& \"]+", r"\1<redacted>", msg)
        msg = msg.translate(CONTROL_CHARS)
        sys.stderr.write(f"{time.strftime('%H:%M:%S')} {self.client_address[0]:<15} {msg}\n")

    def send_common(self, status, ctype, length, extra=None, csp=PAGE_CSP):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", csp)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def send_json(self, obj, status=200, extra=None):
        body = json.dumps(obj).encode()
        self.send_common(status, "application/json", len(body), {"Cache-Control": "no-store", **(extra or {})})
        self.wfile.write(body)

    def error(self, status, msg, close=False):
        if close:
            self.close_connection = True
        self.send_json({"error": msg}, status, {"Connection": "close"} if close else None)

    def send_static(self, path: Path, ctype, cache="no-cache"):
        data = path.read_bytes()
        self.send_common(200, ctype, len(data), {"Cache-Control": cache})
        self.wfile.write(data)

    def send_ca(self):
        self.send_common(200, "application/x-x509-ca-cert", len(self.ca_der),
                         # "inline": with "attachment" iOS Safari saves the file to Files instead of offering
                         # the profile install prompt. Android treats both the same.
                         {"Content-Disposition": 'inline; filename="PhoneDrop-Root-CA.crt"',
                          "Cache-Control": "no-store"}, csp=FILE_CSP)
        self.wfile.write(self.ca_der)

    def read_json(self, limit=256 * 1024):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > limit:
            return None
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, RecursionError):
            return None

    def cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def session_cookie(self, sid, max_age):
        cookie = f"{SESSION_COOKIE}={sid}; Path=/; Max-Age={int(max_age)}; HttpOnly; SameSite=Lax"
        return cookie + "; Secure" if self.is_tls else cookie

    def authed(self):
        sid = self.cookie(SESSION_COOKIE)
        if not self.state.valid_session(sid):
            return False
        self.state.touch_session(sid)
        return True

    def host_ok(self):
        # Rejecting unknown Host headers defeats DNS-rebinding attacks from malicious websites.
        return self.headers.get("Host", "").lower() in self.allowed_hosts

    def csrf_ok(self):
        # Custom header forces a CORS preflight for cross-origin requests (which we never approve);
        # the Origin check is a second layer.
        if self.headers.get("X-PhoneDrop") != "1":
            return False
        origin = self.headers.get("Origin")
        if origin:
            scheme = "https" if self.is_tls else "http"
            return origin.lower() == f"{scheme}://{self.headers.get('Host', '').lower()}"
        return True

    # ---- dispatch

    def setup(self):
        super().setup()
        # Finish the TLS handshake now, under the header deadline, so the idle wait below only ever
        # measures real idle time between requests (the handshake bytes would otherwise count as one).
        if isinstance(self.connection, ssl.SSLSocket):
            self.connection.settimeout(HEADER_TIMEOUT)
            try:
                self.connection.do_handshake()
            except (OSError, ssl.SSLError):
                self.close_connection = True
                raise

    def _wait_for_request(self) -> bool:
        """Block until the client starts sending a request, or give up after KEEPALIVE_IDLE seconds.
        Browsers open connections ahead of time and reuse them later; cutting those at the 20 s
        header deadline made Safari report a lost connection, so idle time is counted separately."""
        conn = self.connection
        if isinstance(conn, ssl.SSLSocket) and conn.pending():
            return True
        try:
            readable, _, _ = select.select([conn], [], [], KEEPALIVE_IDLE)
        except (OSError, ValueError):
            return False
        return bool(readable)

    def handle_one_request(self):
        if not self._wait_for_request():
            self.close_connection = True
            return
        self.connection.settimeout(HEADER_TIMEOUT)  # per read, until parse_request() has the headers
        # ...and an absolute deadline: a client trickling one byte per read must not hold a thread.
        self._watchdog = threading.Timer(HEADER_TIMEOUT, self._drop_connection)
        self._watchdog.daemon = True
        self._watchdog.start()
        try:
            super().handle_one_request()
        except (ConnectionError, ssl.SSLError, TimeoutError, OSError):
            self.close_connection = True
        finally:
            self._watchdog.cancel()

    def _drop_connection(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def parse_request(self):
        ok = super().parse_request()
        self._watchdog.cancel()
        self.connection.settimeout(BODY_TIMEOUT)
        return ok

    def route(self, method):
        if not self.host_ok():
            return self.error(421, "Unknown host", close=True)
        url = urllib.parse.urlsplit(self.path)
        path, query = url.path, urllib.parse.parse_qs(url.query)

        if method == "GET":
            if path == "/pair":
                return self.do_pair(query.get("t", [""])[0])
            if path == "/g":
                return self.do_guest_arrive(query.get("t", [""])[0])
            if path == "/ca.crt":  # public on purpose: phones download it to trust this PC
                return self.send_ca()
            if path.startswith("/static/"):
                name = path[len("/static/"):]
                if name in STATIC_FILES:
                    return self.send_static(STATIC_DIR / name, STATIC_FILES[name])
                return self.error(404, "Not found")
            if path == "/manifest.webmanifest":
                return self.send_static(STATIC_DIR / "manifest.webmanifest", "application/manifest+json")
            if path == "/":
                s = self.state.session_for(self.cookie(SESSION_COOKIE))
                page = ("locked.html" if not s else "pending.html" if s["status"] == "pending"
                        else "guest.html" if s.get("role") == "guest" else "index.html")
                if page in ("index.html", "guest.html"):
                    self.authed()  # updates last_seen
                return self.send_static(STATIC_DIR / page, "text/html; charset=utf-8", "no-store")
            if path == "/api/pair-status":  # the only endpoint a device waiting for approval can reach
                s = self.state.session_for(self.cookie(SESSION_COOKIE))
                if not s:
                    return self.error(404, "No pairing request")
                return self.send_json({"status": s["status"], "name": s["name"]})

        if not self.authed():
            return self.error(401, "Not paired", close=method != "GET")
        if method != "GET" and not self.csrf_ok():
            return self.error(403, "Cross-site request blocked", close=True)

        # Guests get exactly two endpoints: their own info, and upload.
        guest = self.state.session_for(self.cookie(SESSION_COOKIE))
        guest = guest if guest and guest.get("role") == "guest" else None
        if guest:
            if (method, path) == ("GET", "/api/info"):
                return self.send_json({"guest": True, "name": guest["name"], "maxBytes": self.state.max_bytes,
                                       "expires": guest["expires"]})
            if (method, path) == ("POST", "/api/upload"):
                return self.do_upload(guest)
            return self.error(403, "Guests can only upload", close=method != "GET")

        name = urllib.parse.unquote(path.rsplit("/", 1)[-1])
        if path == "/api/devices" or path.startswith("/api/devices/"):
            return self.do_devices(method, path)
        if path == "/api/guest":
            return self.do_guest_link(method)
        if method == "GET":
            if path == "/api/info":
                return self.send_json({"local": self.is_local, "maxBytes": self.state.max_bytes,
                                       "serverCopy": self.is_local and self.state.clipper is not None,
                                       "textCopy": self.is_local and bool(shutil.which("wl-copy")),
                                       "keepDays": self.state.keep_days,
                                       "guestMinutes": self.state.guest_minutes if self.is_local else None,
                                       "folder": str(self.state.store) if self.is_local else None})
            if path == "/api/files":
                return self.do_list(query.get("wait", [None])[0])
            if path == "/api/zip":
                return self.do_zip(query.get("n"))
            if path.startswith("/t/"):
                return self.do_thumb(name, query.get("size", ["480"])[0])
            if path.startswith("/f/"):
                return self.do_file(name, query.get("dl", ["0"])[0] == "1")
        elif method == "POST":
            if path == "/api/upload":
                return self.do_upload()
            if path.startswith("/api/copy/"):
                return self.do_copy(name)
            if path.startswith("/api/prepare/"):
                return self.do_prepare(name)
            if path == "/api/notes":
                return self.do_add_note()
            if path == "/api/delete":
                return self.do_bulk_delete()
            if path.startswith("/api/notes/") and path.endswith("/copy"):
                return self.do_copy_note(path[len("/api/notes/"):-len("/copy")])
            if path == "/api/open-folder":
                return self.do_open_folder()
            if path == "/api/logout":
                self.state.drop_session(self.cookie(SESSION_COOKIE))
                return self.send_json({"ok": True}, extra={"Set-Cookie": f"{SESSION_COOKIE}=; Path=/; Max-Age=0"})
        elif method == "DELETE":
            if path.startswith("/api/files/"):
                return self.do_delete(name)
            if path.startswith("/api/notes/"):
                if not self.state.delete_note(name):
                    return self.error(404, "Not found")
                return self.send_json({"ok": True})
        self.error(404, "Not found", close=method != "GET")

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_DELETE(self):
        self.route("DELETE")

    # ---- endpoints

    def do_pair(self, token):
        ip = self.client_address[0]
        if self.is_loopback and not self.is_local:  # another account here: refused before the lockout counts it
            return self.error(403, "Only the user running PhoneDrop can pair from this computer")
        if self.state.pair_blocked(ip):
            return self.error(429, "Too many failed attempts. Try again later.")
        kind = self.state.check_token(token, self.is_local) if token else None
        if not kind:
            self.state.pair_failed(ip)
            return self.error(403, "Invalid or expired pairing link. Restart PhoneDrop on the computer "
                                   "and scan the new QR code.")
        self.state.pair_succeeded(ip)
        old = self.cookie(SESSION_COOKIE)
        if old:  # scanning again replaces this browser's previous session instead of piling up records
            self.state.drop_session(old)
        # The PC's own one-time code proves it is this computer; a scanned QR needs approval on the PC.
        status = "active" if kind == "local" or self.state.no_confirm else "pending"
        sid, rec = self.state.new_session(ip, self.headers.get("User-Agent", ""), status)
        if not sid:
            return self.error(429, "Too many pending requests; approve or deny the existing ones first")
        cookie = self.session_cookie(sid, SESSION_TTL)
        if status == "pending":
            msg = f"{rec['name']} ({ip}) wants to pair"
            self.log_message("%s — approve it in the panel: http://127.0.0.1:%d", msg, self.local_port)
            notify(msg)
        else:
            self.log_message("paired new device: %s", rec["name"])
        # Redirect strips the token from the address bar / history.
        self.send_common(303, "text/plain", 0, {"Location": "/", "Set-Cookie": cookie, "Cache-Control": "no-store"})

    def do_guest_arrive(self, token):
        """A guest opened a drop link: trade the one-time token for a short upload-only session."""
        st, ip = self.state, self.client_address[0]
        old = st.session_for(self.cookie(SESSION_COOKIE))
        if old and old.get("role") == "device" and old["status"] == "active":
            # Already paired (e.g. the owner tested the link): keep that session, leave the token unused.
            return self.send_common(303, "text/plain", 0, {"Location": "/", "Cache-Control": "no-store"})
        if self.is_loopback and not self.is_local:  # another account here: refused before the lockout counts it
            return self.error(403, "Only the user running PhoneDrop can use this from this computer")
        if st.pair_blocked(ip):
            return self.error(429, "Too many failed attempts. Try again later.")
        if not token or not st.consume_guest_token(token):
            st.pair_failed(ip)
            return self.error(403, "This guest link is invalid or has expired.")
        st.pair_succeeded(ip)
        if old:  # a pending request or an earlier guest visit from this browser
            st.drop_session(self.cookie(SESSION_COOKIE))
        ttl = st.guest_minutes * 60
        sid, rec = st.new_session(ip, self.headers.get("User-Agent", ""), "active", role="guest", ttl=ttl)
        msg = f"guest arrived: {rec['name']} ({ip})"
        self.log_message("%s", msg)
        notify(msg)
        self.send_common(303, "text/plain", 0, {"Location": "/", "Set-Cookie": self.session_cookie(sid, ttl),
                                                "Cache-Control": "no-store"})

    def do_guest_link(self, method):
        """Create (POST) or revoke (DELETE) the guest drop link. Only from this computer."""
        if not self.is_local:
            return self.error(403, "Only available on this computer", close=method != "GET")
        st = self.state
        if method == "POST":
            token, expires = st.create_guest_token()
            url = f"{self.phone_base}/g?t={token}"
            self.log_message("created a guest link (valid until %s)", time.strftime("%H:%M", time.localtime(expires)))
            return self.send_json({"url": url, "expires": expires, "qr": qr_data_url(url)})
        if method == "DELETE":
            n = st.revoke_guest_tokens()
            if n:
                self.log_message("revoked the guest link")
            return self.send_json({"ok": True, "revoked": n})
        return self.error(405, "Method not allowed", close=method != "GET")

    def do_list(self, wait):
        st = self.state
        if wait is not None and wait != "":
            deadline = time.time() + LONG_POLL_SECONDS
            while st.version() == wait and time.time() < deadline:
                time.sleep(0.4)
        body = {"version": st.version(), "files": st.listing(), "notes": list(reversed(st.notes))}
        if self.is_local:
            body["pending"] = st.pending_devices()
        self.send_json(body)

    def do_devices(self, method, path):
        """Device panel: list, approve/deny pairing requests, revoke. Only from this computer."""
        if not self.is_local:
            return self.error(403, "Only available on this computer", close=method != "GET")
        st = self.state
        if method == "GET" and path == "/api/devices":
            return self.send_json({"devices": st.devices(self.cookie(SESSION_COOKIE))})
        if method == "DELETE" and path == "/api/devices":  # everything except this computer's own session
            n = st.remove_all_devices(self.cookie(SESSION_COOKIE))
            self.log_message("revoked all devices (%d)", n)
            return self.send_json({"revoked": n})
        m = re.fullmatch(r"/api/devices/([\w-]{1,32})(?:/(approve|deny))?", path)
        if not m:
            return self.error(404, "Not found", close=method != "GET")
        did, action = m.groups()
        if method == "POST" and action == "approve":
            rec = st.approve_device(did)
            if not rec:
                return self.error(404, "No such pairing request (it may have expired)")
            self.log_message("approved %s (%s)", rec["name"], rec["ip"])
            return self.send_json({"ok": True})
        if (method == "POST" and action == "deny") or (method == "DELETE" and not action):
            rec = st.remove_device(did)
            if not rec:
                return self.error(404, "No such device")
            self.log_message("%s %s (%s)", "denied" if action else "revoked", rec["name"], rec["ip"])
            return self.send_json({"ok": True})
        return self.error(404, "Not found", close=method != "GET")

    def do_file(self, name, download):
        p = self.state.resolve(name)
        if not p:
            return self.error(404, "Not found")
        ext = p.suffix[1:].lower()
        kind = kind_of(ext)
        size = p.stat().st_size
        # Only images, audio/video and PDFs are ever shown inline; anything else is a download.
        inline = not download and kind in ("image", "video", "audio", "pdf")
        quoted = urllib.parse.quote(p.name)
        headers = {
            "Content-Disposition": f"{'inline' if inline else 'attachment'}; filename*=UTF-8''{quoted}",
            "Cache-Control": "private, max-age=86400",
            "Accept-Ranges": "bytes",
        }
        # Chrome's PDF viewer refuses to render under a CSP sandbox; it runs in its own sandbox anyway.
        csp = "default-src 'none'" if kind == "pdf" else FILE_CSP
        start, end = 0, size - 1
        status = 200
        m = re.fullmatch(r"bytes=(\d{0,18})-(\d{0,18})", self.headers.get("Range", ""))  # longer: served whole
        if m and size and (m.group(1) or m.group(2)):
            if m.group(1):
                start = int(m.group(1))
                end = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
            else:  # suffix range: the last N bytes
                start = max(0, size - int(m.group(2)))
            if start > end or start >= size:
                return self.send_common(416, "text/plain", 0, {"Content-Range": f"bytes */{size}"})
            status = 206
            headers["Content-Range"] = f"bytes {start}-{end}/{size}"
        length = end - start + 1 if size else 0
        self.send_common(status, MIME[ext] if inline else "application/octet-stream", length, headers, csp=csp)
        with open(p, "rb") as f:
            f.seek(start)
            remaining = length
            while remaining > 0:
                chunk = f.read(min(256 * 1024, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def do_zip(self, names=None):
        if names is not None:
            names = list(dict.fromkeys(names[:1000]))  # each file once, in the order asked
            paths = [p for p in (self.state.resolve(n) for n in names) if p]
            if not paths:
                return self.error(404, "No such files")
        else:
            paths = [p for p in (self.state.resolve(f["name"]) for f in self.state.listing()) if p]
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", f"attachment; filename=\"phonedrop-{time.strftime('%Y%m%d-%H%M%S')}.zip\"")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        # Images are already compressed, so ZIP_STORED is fast and loses nothing.
        with zipfile.ZipFile(self.wfile, "w", zipfile.ZIP_STORED) as z:
            for p in paths:
                if p.is_file():
                    z.write(p, p.name)

    def do_upload(self, guest=None):
        st = self.state
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.error(411, "Content-Length required", close=True)
        if length <= 0:
            return self.error(400, "Empty file", close=True)
        if length > st.max_bytes:
            return self.error(413, f"File too large (max {human(st.max_bytes)})", close=True)
        reserved = length
        with st.lock:  # uploads still in progress count as used, so parallel ones can't overfill the disk
            if shutil.disk_usage(st.store).free < length + st.inflight + DISK_RESERVE:
                return self.error(507, "Not enough disk space on the computer", close=True)
            st.inflight += reserved

        raw = self.headers.get("X-Filename", "image")  # http.server decodes headers as latin-1
        orig = urllib.parse.unquote(raw.encode("latin-1", "replace").decode("utf-8", "replace"))[:255]
        tmp = st.partial / f"{secrets.token_hex(8)}.part"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError:
            with st.lock:
                st.inflight -= reserved
            raise
        try:
            with os.fdopen(fd, "wb") as out:
                remaining, head = length, b""
                while remaining:
                    chunk = self.rfile.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        raise ConnectionError("client disconnected")
                    if len(head) < SNIFF_BYTES:
                        head += chunk[:SNIFF_BYTES - len(head)]
                    out.write(chunk)
                    remaining -= len(chunk)
            claimed = claimed_extension(orig)
            ext = sniff_type(head, claimed)
            if not ext:
                tmp.unlink(missing_ok=True)
                return self.error(415, f"Unsupported file type{' (.' + claimed + ')' if claimed else ''}")
            kind = kind_of(ext)

            stripped = False
            if not st.keep_metadata:
                if kind == "image":
                    stripped = strip_metadata(tmp, ext)
                    if not stripped and ext in STRIPPABLE:  # never keep a photo we couldn't clean
                        tmp.unlink(missing_ok=True)
                        return self.error(415, "The image file is malformed")
                elif kind == "video":
                    # ffmpeg runs in this request's thread; only a couple at a time, so a burst of
                    # video uploads can't tie up every worker.
                    if not VIDEO_SLOTS.acquire(timeout=30):
                        tmp.unlink(missing_ok=True)
                        return self.error(503, "Busy processing other videos, try again in a moment", close=True)
                    try:
                        stripped = strip_video(tmp, ext)
                    finally:
                        VIDEO_SLOTS.release()
            if stripped:
                length = tmp.stat().st_size
            stem = safe_stem(orig, kind)
            if guest:  # so you can tell at a glance what came from outside
                stem = "guest-" + stem
            os.chmod(tmp, 0o600)
            for i in range(10000):
                final = st.store / (f"{stem}.{ext}" if i == 0 else f"{stem}-{i}.{ext}")
                try:
                    os.link(tmp, final)  # atomic, fails if the name is taken
                    break
                except FileExistsError:
                    continue
            else:
                return self.error(409, "Could not pick a file name")
            meta = ("metadata stripped" if stripped else "metadata kept" if st.keep_metadata
                    else "metadata kept: can't strip ." + ext if kind in ("image", "video") else "")
            self.log_message("received %s (%s%s)%s", final.name, human(length), ", " + meta if meta else "",
                             f" from guest {guest['name']}" if guest else "")
            if st.clipper and kind == "image":
                st.clipper.request(final.name)
            if st.hasher:
                st.hasher.request(final.name)
            # "kept" tells the uploader that location and device tags may still be in the file.
            kept = kind in ("image", "video") and ext not in ("gif", "bmp")
            self.send_json({"name": final.name, "size": length,
                            "meta": "stripped" if stripped else "kept" if kept else None}, 201)
        except (ConnectionError, TimeoutError, ssl.SSLError):
            self.close_connection = True
        finally:
            tmp.unlink(missing_ok=True)
            with st.lock:
                st.inflight -= reserved

    def do_thumb(self, name, size):
        p = self.state.resolve(name)
        size = int(size) if size.isdigit() and int(size) in THUMB_SIZES else THUMB_SIZES[0]
        t = self.state.thumbnail(p, size) if p else None
        if not t:
            return self.error(404, "No preview")
        data = t.read_bytes()
        self.send_common(200, "image/jpeg", len(data), {"Cache-Control": "private, max-age=604800"}, csp=FILE_CSP)
        self.wfile.write(data)

    def do_delete(self, name):
        if not self.state.remove_file(name):
            return self.error(404, "Not found")
        self.send_json({"ok": True})

    def do_bulk_delete(self):
        body = self.read_json()
        names = body.get("names") if isinstance(body, dict) else None
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            return self.error(400, "Expected a list of file names")
        deleted = sum(self.state.remove_file(n) for n in names[:1000])
        self.log_message("deleted %d file(s)", deleted)
        self.send_json({"deleted": deleted})

    def do_copy(self, name):
        clipper = self.state.clipper
        if not self.is_local or not clipper:
            return self.error(403, "Server-side copy is only available on this computer")
        p = self.state.resolve(name)
        if not p:
            return self.error(404, "Not found")
        src, mime = clipper.ready_source(p), "image/png"
        if not src:
            status, _ = clipper.status(p)
            if status != "error":
                if status == "none":
                    clipper.request(p.name, front=True)
                return self.error(409, "Still converting — try again in a moment")
            src, mime = p, MIME[p.suffix[1:].lower()]  # conversion failed: copy the original as-is
        try:
            with open(src, "rb") as f:
                # wl-copy forks a background process that owns the clipboard. Its output must not be
                # piped to us, or run() would wait for that background process to exit.
                r = subprocess.run(["wl-copy", "--type", mime], stdin=f, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=30)
        except subprocess.TimeoutExpired:
            return self.error(500, "wl-copy timed out")
        if r.returncode:
            return self.error(500, "wl-copy failed")
        clipper.touch(src)
        self.send_json({"ok": True, "type": mime})

    def do_prepare(self, name):
        clipper = self.state.clipper
        p = self.state.resolve(name)
        if not self.is_local or not clipper:
            return self.error(403, "Only available on this computer")
        if not p:
            return self.error(404, "Not found")
        clipper.failed.discard(clipper.path(p).name)
        if not clipper.ready_source(p):
            clipper.request(p.name, front=True)
        self.send_json({"ok": True})

    def do_add_note(self):
        body = self.read_json()
        text = body.get("text") if isinstance(body, dict) else None
        if not isinstance(text, str) or not text.strip():
            return self.error(400, "Nothing to send")
        if len(text) > NOTE_MAX_CHARS:
            return self.error(413, f"Text too long (max {NOTE_MAX_CHARS} characters)")
        note = self.state.add_note(text.replace("\r\n", "\n").strip())
        self.log_message("received text (%d chars)", len(note["text"]))
        self.send_json(note, 201)

    def do_copy_note(self, nid):
        if not self.is_local or not shutil.which("wl-copy"):
            return self.error(403, "Server-side copy is only available on this computer")
        note = self.state.find_note(nid)
        if not note:
            return self.error(404, "Not found")
        try:
            r = subprocess.run(["wl-copy", "--type", "text/plain;charset=utf-8"], input=note["text"].encode(),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        except subprocess.TimeoutExpired:
            return self.error(500, "wl-copy timed out")
        if r.returncode:
            return self.error(500, "wl-copy failed")
        self.send_json({"ok": True})

    def do_open_folder(self):
        if not self.is_local:
            return self.error(403, "Only available on this computer")
        subprocess.Popen(["xdg-open", str(self.state.store)], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
        self.send_json({"ok": True})


class LimitedServer:
    """Mixin for both listeners: caps open connections in total and per client IP, so idle or slow
    clients can't pile up threads. A connection over the limit is closed straight away."""
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.per_ip = {}  # ip -> open connections
        self.per_ip_lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        ip = client_address[0]
        if not self.slots.acquire(blocking=False):
            return self.shutdown_request(request)
        with self.per_ip_lock:
            if self.per_ip.get(ip, 0) >= MAX_CONNECTIONS_PER_IP:
                self.slots.release()
                return self.shutdown_request(request)
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
        try:
            super().process_request(request, client_address)
        except BaseException:  # the worker thread didn't start, so it won't release the slot
            self._release(ip)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release(client_address[0])

    def _release(self, ip):
        with self.per_ip_lock:
            n = self.per_ip.get(ip, 0) - 1
            if n > 0:
                self.per_ip[ip] = n
            else:
                self.per_ip.pop(ip, None)
        self.slots.release()


class TLSServer(LimitedServer, ThreadingHTTPServer):
    def __init__(self, addr, handler, ctx):
        self.ctx = ctx
        super().__init__(addr, handler)

    def get_request(self):
        sock, addr = self.socket.accept()
        # Handshake happens lazily in the worker thread, so a stalled client can't block accept().
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr


class PlainServer(LimitedServer, ThreadingHTTPServer):
    pass


# ---------------------------------------------------------------- TLS cert

def openssl(*args):
    return subprocess.run(["openssl", *args], check=True, capture_output=True)


CA_VERSION = 2  # 2: the root carries name constraints (cert.json "ca"); older roots are replaced
LEAF_VERSION = 2  # 2: no hostname in the SAN (cert.json "leaf"); older leaves are re-issued, the root stays
# The only addresses and names the root may vouch for: private, CGNAT, link-local and loopback IPs,
# and *.local / localhost. A leaked root key then can't be used to impersonate any public site.
CA_PERMITTED_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16")]
CA_NAME_CONSTRAINTS = "nameConstraints=critical," + ",".join(
    [f"permitted;IP:{n.network_address}/{n.netmask}" for n in CA_PERMITTED_NETS]
    + ["permitted;DNS:.local", "permitted;DNS:localhost"])


def ca_constrained(ca: Path) -> bool:
    r = subprocess.run(["openssl", "x509", "-noout", "-text", "-in", str(ca)], capture_output=True, text=True)
    return r.returncode == 0 and "X509v3 Name Constraints: critical" in r.stdout


def ensure_ca():
    """Private root CA, made once. A phone that installs it trusts every leaf it signs, within the
    addresses and names in CA_NAME_CONSTRAINTS."""
    ca, ca_key = CONFIG_DIR / "ca.pem", CONFIG_DIR / "ca-key.pem"
    if ca.exists() and ca_key.exists():
        try:
            version = json.loads((CONFIG_DIR / "cert.json").read_text()).get("ca")
        except (OSError, ValueError, AttributeError):
            version = None
        if version == CA_VERSION and ca_constrained(ca):
            return ca, ca_key
        print("Replacing the PhoneDrop root certificate with one that is limited to local addresses.\n"
              "  NOTE: a phone that installed the old root must install the new one from /ca.crt\n"
              "  (and can remove the old one), or it will show a certificate warning again.")
    else:
        print("Generating the PhoneDrop root certificate (once)…")
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca), "-days", "3650", "-subj", "/CN=PhoneDrop Root CA/O=PhoneDrop",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash", "-addext", CA_NAME_CONSTRAINTS)
    os.chmod(ca_key, 0o600)
    return ca, ca_key


def ensure_cert(ips):
    """Leaf certificate for the current LAN IPs, signed by the root; only the leaf is re-issued when they
    change. Returns (leaf, key, root, chain); chain.pem is leaf + root, which is what the server sends."""
    cert, key, meta = CONFIG_DIR / "cert.pem", CONFIG_DIR / "key.pem", CONFIG_DIR / "cert.json"
    want = sorted(set(ips) | {"127.0.0.1"})
    ca, ca_key = ensure_ca()
    cert, key = _ensure_leaf(cert, key, meta, want, ca, ca_key)
    chain = CONFIG_DIR / "chain.pem"
    pem = cert.read_text() + ca.read_text()
    if not chain.exists() or chain.read_text() != pem:  # follows every change of the leaf or the root
        chain.write_text(pem)
    return cert, key, ca, chain


def _ensure_leaf(cert, key, meta, want, ca, ca_key):
    # A leaf from the old self-signed layout, or signed by a root that has since been replaced, fails this.
    signed = cert.exists() and key.exists() and subprocess.run(
        ["openssl", "verify", "-CAfile", str(ca), str(cert)], capture_output=True).returncode == 0
    try:
        info = json.loads(meta.read_text())
        if (signed and info.get("ca") == CA_VERSION and info.get("leaf") == LEAF_VERSION
                and set(want) <= set(info["ips"]) and info["expires"] > time.time() + 7 * 86400):
            return cert, key
        migrate = info.get("ca") != CA_VERSION or not signed
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        migrate = True
    if cert.exists() and migrate:
        print("Replacing the old certificate with one signed by the PhoneDrop root certificate.")
    else:
        print("Issuing a new TLS certificate for this computer's addresses…")
    # The root can't vouch for addresses outside its name constraints, so those stay out of the leaf.
    covered = [ip for ip in want if any(ipaddress.ip_address(ip) in n for n in CA_PERMITTED_NETS)]
    for ip in sorted(set(want) - set(covered)):
        print(f"  WARNING: {ip} is not a private address, so the certificate can't cover it. The phone must use "
              f"one of: {', '.join(covered)}")
    san = ",".join([f"IP:{ip}" for ip in covered] + ["DNS:localhost"])  # no hostname: it would name the owner to the LAN
    days = 825  # Apple's maximum for TLS server certificates
    csr, ext = CONFIG_DIR / "leaf.csr.tmp", CONFIG_DIR / "leaf.ext.tmp"
    try:
        ext.write_text(f"subjectAltName={san}\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
                       "keyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                "-keyout", str(key), "-subj", "/CN=PhoneDrop", "-out", str(csr))
        os.chmod(key, 0o600)
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial",
                "-days", str(days), "-extfile", str(ext), "-out", str(cert))
    finally:
        csr.unlink(missing_ok=True)
        ext.unlink(missing_ok=True)
    meta.write_text(json.dumps({"ips": want, "expires": time.time() + days * 86400, "ca": CA_VERSION, "leaf": LEAF_VERSION}))
    return cert, key


def cert_fingerprint(cert: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def notify(msg: str):
    """Desktop notification, if notify-send is available. Never blocks the request."""
    if not shutil.which("notify-send"):
        return
    try:
        proc = subprocess.Popen(["notify-send", "-a", "PhoneDrop", "PhoneDrop", msg], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        threading.Thread(target=proc.wait, daemon=True).start()  # reap it, so no zombie is left behind
    except OSError:
        pass


def qr_data_url(url):
    """The URL as a QR code PNG data: URL for the panel, or None without a working qrencode."""
    if not shutil.which("qrencode"):
        return None
    try:
        # The URL goes in on stdin, so other users can't read the secret in it from `ps`.
        r = subprocess.run(["qrencode", "-t", "PNG", "-s", "8", "-m", "2", "-o", "-"], input=url.encode(),
                           capture_output=True, timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode or not r.stdout.startswith(b"\x89PNG"):
        return None
    return "data:image/png;base64," + base64.b64encode(r.stdout).decode()


def print_qr(url):
    if shutil.which("qrencode"):
        subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "2"], input=url.encode())  # stdin: not in `ps`
    else:
        print("(install `qrencode` to show a QR code here)")


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Receive photos, videos and files from your phone over the local network.")
    ap.add_argument("--port", type=int, default=8443, help="HTTPS port for the phone (default 8443)")
    ap.add_argument("--local-port", type=int, default=8080, help="localhost HTTP port for this computer (default 8080)")
    ap.add_argument("--bind", help="address for the LAN listener (default: this computer's LAN address; "
                                   "0.0.0.0 = all interfaces)")
    ap.add_argument("--dir", default=str(Path.home() / "Pictures" / "PhoneDrop"), help="where images are saved")
    ap.add_argument("--max-mb", type=int, default=2048, help="max size per file in MB (default 2048)")
    ap.add_argument("--clip-cache", type=int, default=CLIP_KEEP,
                    help=f"keep ready-to-paste PNGs for this many recent images (default {CLIP_KEEP}, ~17 MB each)")
    ap.add_argument("--pair-minutes", type=int, default=PAIR_MINUTES,
                    help=f"how long after startup new devices can pair (default {PAIR_MINUTES}, 0 = no limit)")
    ap.add_argument("--keep-days", type=int, default=0,
                    help="delete received files and notes after this many days (default 0 = keep forever)")
    ap.add_argument("--keep-metadata", action="store_true",
                    help="don't strip EXIF/XMP metadata (GPS location, phone model…) from received images")
    ap.add_argument("--guest-minutes", type=int, default=GUEST_MINUTES,
                    help=f"how long a guest can upload after opening a guest link (default {GUEST_MINUTES})")
    ap.add_argument("--no-confirm", action="store_true", help="pair devices without approval on the PC")
    ap.add_argument("--new-token", action="store_true", help="unpair all devices")
    ap.add_argument("--no-browser", action="store_true", help="don't open the panel in your browser")
    args = ap.parse_args()

    state = State(Path(args.dir).expanduser().resolve(), args.max_mb * 1024 * 1024, args.new_token,
                  args.pair_minutes, args.keep_metadata, max(0, args.keep_days), args.no_confirm,
                  max(1, args.guest_minutes))
    probe_sandbox()  # after State(): the config directory it binds must exist
    threading.Thread(target=state.sessions_forever, daemon=True).start()
    if state.keep_days:
        threading.Thread(target=state.cleanup_forever, daemon=True).start()
    if shutil.which("wl-copy") and (shutil.which("vips") or shutil.which("magick")):
        state.clipper = Clipper(state, max(1, args.clip_cache))
        state.clipper.scan()
    state.hasher = Hasher(state)
    state.hasher.scan()
    ips = lan_ips()
    ip = primary_ip()
    bind = args.bind or ip
    cert, key, ca, chain = ensure_cert(ips)

    hosts = {f"127.0.0.1:{args.local_port}", f"localhost:{args.local_port}",
             f"127.0.0.1:{args.port}", f"localhost:{args.port}",
             }
    hosts |= {f"{a}:{args.port}" for a in ips}
    Handler.state = state
    Handler.allowed_hosts = hosts
    Handler.local_port = args.local_port
    Handler.phone_base = f"https://{ip}:{args.port}"
    Handler.ca_der = ssl.PEM_cert_to_DER_cert(ca.read_text())
    Handler.check_uid = os.path.exists(TCP_TABLES[0])
    if not Handler.check_uid:
        print("WARNING: /proc/net/tcp is not available, so every account on this computer counts as "
              "'this computer' (loopback only).")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(chain, key)  # leaf + root, so the phone's certificate viewer shows the root

    try:
        lan = TLSServer((bind, args.port), Handler, ctx)
        local = PlainServer(("127.0.0.1", args.local_port), Handler)
    except OSError as e:
        sys.exit(f"Could not start server: {e}  (is PhoneDrop already running? try --port / --local-port)")

    for srv in (lan, local):
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    phone_url = f"https://{ip}:{args.port}/pair?t={state.token}"
    pc_url = f"http://127.0.0.1:{args.local_port}/pair?t={state.local_code}"

    print("\n  PhoneDrop is running")
    print(f"  Saving to:   {state.store}" + (f"  (deleted after {state.keep_days} day(s))" if state.keep_days else ""))
    print(f"  This PC:     http://127.0.0.1:{args.local_port}")
    print(f"  Phone:       https://{ip}:{args.port}   (same Wi-Fi)")
    print("  Decoders:    " + ("sandboxed with bubblewrap" if SANDBOX else
                              "NOT sandboxed (install bubblewrap to isolate image/video decoders)"))
    print(f"  Root CA SHA-256 {cert_fingerprint(ca)}   <- compare this one on the phone")
    print(f"  Cert SHA-256    {cert_fingerprint(cert)}")
    print("\n  Scan with your phone camera to pair (until the root certificate is installed, your browser")
    print("  warns about the certificate — check the root fingerprint above and continue):\n")
    print_qr(phone_url)
    print("  Keep this QR private: anyone who scans it can upload to and read from the panel"
          + ("." if state.no_confirm else " once you approve them."))
    if not state.no_confirm:
        print(f"  New devices must be approved in the panel on this computer (http://127.0.0.1:{args.local_port}).")
    if state.pair_until:
        print(f"  Pairing is open until {time.strftime('%H:%M', time.localtime(state.pair_until))}; "
              "restart PhoneDrop to pair another device later.")
    print("  To stop the certificate warning for good, install the root certificate on the phone:")
    print(f"  https://{ip}:{args.port}/ca.crt (see README)")
    print("  Run with --new-token to unpair every device.  Ctrl+C to stop.\n")
    if bind != "0.0.0.0" and not ipaddress.ip_address(bind).is_private:
        print(f"  WARNING: {bind} is not a private address. The phone port may be reachable from the internet.\n")

    if not args.no_browser and shutil.which("xdg-open"):
        subprocess.Popen(["xdg-open", pc_url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    else:  # the terminal belongs to this user, so the one-time code can be shown here
        print(f"  Open the panel on this computer (works once, for {LOCAL_CODE_TTL // 60} minutes):\n  {pc_url}\n")

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nStopping.")
        state.flush_sessions()
        lan.shutdown()
        local.shutdown()


if __name__ == "__main__":
    main()
