#!/usr/bin/env python3
"""PhoneDrop — send photos, videos and files from your phone to this computer over the local network.

Two listeners:
  * HTTPS on the LAN (default :8443) for the phone (self-signed cert, generated on first run)
  * HTTP on 127.0.0.1 (default :8080) for this computer's browser (localhost is a secure
    context, so clipboard copy works without certificate warnings)

Access requires pairing: scan the QR code printed in the terminal. The pairing secret is new on
every run and only works for a few minutes after startup. Pairing sets a long-lived HttpOnly
session cookie. Run with --new-token to revoke every paired device.
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
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
}
CLIP_KEEP = 30  # PNG clipboard copies kept for this many most-recently-used images
THUMB_SIZES = (480, 1600)  # grid, and the viewer for formats browsers can't display (HEIC/TIFF)
NOTE_MAX_CHARS = 20000
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
    if head.startswith(b"BM") and len(head) > 14:
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


def strip_video(path: Path, ext: str) -> bool:
    """Remux the video without its global metadata (GPS, device). Streams are copied, not re-encoded."""
    if ext not in ("mp4", "m4v", "mov", "3gp") or not shutil.which("ffmpeg"):
        return False
    fmt = {"mov": "mov", "3gp": "3gp"}.get(ext, "mp4")
    tmp = path.with_name(path.name + ".strip")
    try:
        r = subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(path), "-map", "0", "-map_metadata", "-1",
                            "-c", "copy", "-movflags", "+faststart", "-f", fmt, str(tmp)],
                           capture_output=True, timeout=600)
        if r.returncode or not tmp.exists() or not tmp.stat().st_size:
            tmp.unlink(missing_ok=True)
            return False
        os.replace(tmp, path)
        return True
    except subprocess.TimeoutExpired:
        tmp.unlink(missing_ok=True)
        return False


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


def strip_jpeg(src, dst):
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
            src.seek(-1, 1)
            continue
        if kind == 0xDA:  # start of scan: write orientation, then copy the image data up to EOI
            if orientation and orientation != 1:
                dst.write(minimal_exif(orientation))
            dst.write(marker)
            _copy_until(src, dst, b"\xff\xd9")
            return
        length = int.from_bytes(src.read(2), "big")
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
    sig = src.read(8)
    if sig != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    dst.write(sig)
    while True:
        head = src.read(8)
        if len(head) < 8:
            raise ValueError("truncated")
        length = int.from_bytes(head[:4], "big")
        kind = head[4:]
        body = src.read(length + 4)
        if len(body) != length + 4:
            raise ValueError("truncated chunk")
        if kind not in PNG_DROP:
            dst.write(head + body)
        if kind == b"IEND":
            return


def strip_webp(src, dst):
    head = src.read(12)
    if head[:4] != b"RIFF" or head[8:] != b"WEBP":
        raise ValueError("not a WebP")
    chunks = []
    while True:
        h = src.read(8)
        if len(h) < 8:
            break
        size = int.from_bytes(h[4:], "little")
        body = src.read(size + (size & 1))
        if len(body) < size:
            raise ValueError("truncated chunk")
        if h[:4] in (b"EXIF", b"XMP "):
            continue
        if h[:4] == b"VP8X":
            body = bytes([body[0] & ~0x0C]) + body[1:]  # clear the EXIF and XMP flags
        chunks.append(h + body)
    total = sum(len(c) for c in chunks) + 4
    dst.write(b"RIFF" + total.to_bytes(4, "little") + b"WEBP")
    for c in chunks:
        dst.write(c)


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
    except (ValueError, OSError):
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


def primary_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


# ---------------------------------------------------------------- state

class State:
    def __init__(self, store: Path, max_bytes: int, new_token: bool, pair_minutes: int, keep_metadata=False):
        self.store = store
        self.keep_metadata = keep_metadata
        self.partial = store / ".partial"
        self.thumbs = store / ".thumbs"
        self.thumb_locks = {}
        self.thumb_slots = threading.BoundedSemaphore(2)  # cap concurrent decoders
        self.max_bytes = max_bytes
        self.clipper = None
        self.notes_file = store / ".notes.json"
        self.notes_tick = 0
        try:
            self.notes = [n for n in json.loads(self.notes_file.read_text())
                          if isinstance(n, dict) and isinstance(n.get("text"), str)]
        except (OSError, ValueError):
            self.notes = []
        self.lock = threading.Lock()
        self.fails = {}  # ip -> [count, first_ts]
        CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(CONFIG_DIR, 0o700)
        store.mkdir(parents=True, exist_ok=True, mode=0o700)
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
        try:
            self.sessions = json.loads(self.sessions_file.read_text())
        except (OSError, ValueError):
            self.sessions = {}
        now = time.time()
        self.sessions = {k: v for k, v in self.sessions.items() if v.get("expires", 0) > now}

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

    def new_session(self, ip: str, ua: str) -> str:
        sid = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[self._h(sid)] = {"expires": time.time() + SESSION_TTL, "ip": ip, "ua": ua[:200],
                                           "created": time.strftime("%Y-%m-%d %H:%M:%S")}
            self._write_private(self.sessions_file, json.dumps(self.sessions, indent=1))
        return sid

    def valid_session(self, sid: str) -> bool:
        if not sid:
            return False
        s = self.sessions.get(self._h(sid))
        return bool(s and s["expires"] > time.time())

    def drop_session(self, sid: str):
        with self.lock:
            if self.sessions.pop(self._h(sid), None) is not None:
                self._write_private(self.sessions_file, json.dumps(self.sessions, indent=1))

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

    def check_token(self, t: str, local: bool) -> bool:
        t = t.encode()
        with self.lock:
            if local and self.local_code and hmac.compare_digest(t, self.local_code.encode()):
                self.local_code = None
                return True
        return self.pairing_open() and hmac.compare_digest(t, self.token.encode())

    # ---- files

    def version(self) -> str:
        tick = self.clipper.tick if self.clipper else 0
        return f"{self.store.stat().st_mtime_ns}.{tick}.{self.notes_tick}"

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
            kind = kind_of(p.suffix[1:].lower())
            if kind == "video" and shutil.which("ffmpeg"):
                # A frame from one second in (or the first frame for very short clips).
                for ss in ("1", "0"):
                    cmds.append(["ffmpeg", "-v", "error", "-y", "-ss", ss, "-i", str(p), "-frames:v", "1",
                                 "-vf", f"scale='min({size},iw)':-2", "-q:v", "4", "-f", "image2", str(tmp)])
            elif kind == "pdf" and shutil.which("magick"):
                cmds.append(["magick", "-density", "72", f"{p}[0]", "-background", "white", "-alpha", "remove",
                             "-thumbnail", f"{size}x{size}>", "-quality", "78", "-strip", f"jpg:{tmp}"])
            elif kind == "image":
                if shutil.which("vipsthumbnail"):
                    cmds.append(["vipsthumbnail", str(p), "-s", f"{size}x{size}", "-o", f"{tmp}[Q=78,strip]"])
                if shutil.which("magick"):
                    cmds.append(["magick", f"{p}[0]", "-auto-orient", "-thumbnail", f"{size}x{size}>",
                                 "-quality", "78", "-strip", f"jpg:{tmp}"])
            try:
                for cmd in cmds:
                    try:
                        r = subprocess.run(cmd, capture_output=True, timeout=60)
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
        try:
            if shutil.which("vips") and self._vips(src, tmp):
                pass
            elif shutil.which("magick"):
                r = subprocess.run(["magick", f"{src}[0]", "-auto-orient", "-define", "png:compression-level=1",
                                    f"png:{tmp}"], capture_output=True, timeout=180)
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
        proc = subprocess.Popen(["vips", "--vips-progress", "autorot", str(src), f"{tmp}[compression=1]"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
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


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "PhoneDrop"
    sys_version = ""
    timeout = 60  # per-socket-op timeout; guards against slow-loris connections
    # Send each response as a single write with Nagle off. Otherwise headers and body go out as separate
    # small packets and TCP delayed-ACK adds ~40 ms (much more on a phone's Wi-Fi) to every request.
    disable_nagle_algorithm = True
    wbufsize = 64 * 1024

    state: State = None
    allowed_hosts: set = set()

    # ---- helpers

    @property
    def is_tls(self):
        return isinstance(self.connection, ssl.SSLSocket)

    @property
    def is_local(self):
        return ipaddress.ip_address(self.client_address[0]).is_loopback

    def log_message(self, fmt, *args):
        msg = fmt % args
        msg = re.sub(r"([?&]t=)[^& \"]+", r"\1<redacted>", msg)
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

    def read_json(self, limit=256 * 1024):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > limit:
            return None
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return None

    def cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def authed(self):
        return self.state.valid_session(self.cookie(SESSION_COOKIE))

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

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionError, ssl.SSLError, TimeoutError):
            self.close_connection = True

    def route(self, method):
        if not self.host_ok():
            return self.error(421, "Unknown host", close=True)
        url = urllib.parse.urlsplit(self.path)
        path, query = url.path, urllib.parse.parse_qs(url.query)

        if method == "GET":
            if path == "/pair":
                return self.do_pair(query.get("t", [""])[0])
            if path.startswith("/static/"):
                name = path[len("/static/"):]
                if name in STATIC_FILES:
                    return self.send_static(STATIC_DIR / name, STATIC_FILES[name])
                return self.error(404, "Not found")
            if path == "/manifest.webmanifest":
                return self.send_static(STATIC_DIR / "manifest.webmanifest", "application/manifest+json")
            if path == "/":
                page = "index.html" if self.authed() else "locked.html"
                return self.send_static(STATIC_DIR / page, "text/html; charset=utf-8", "no-store")

        if not self.authed():
            return self.error(401, "Not paired", close=method != "GET")
        if method != "GET" and not self.csrf_ok():
            return self.error(403, "Cross-site request blocked", close=True)

        name = urllib.parse.unquote(path.rsplit("/", 1)[-1])
        if method == "GET":
            if path == "/api/info":
                return self.send_json({"local": self.is_local, "maxBytes": self.state.max_bytes,
                                       "serverCopy": self.is_local and self.state.clipper is not None,
                                       "textCopy": self.is_local and bool(shutil.which("wl-copy")),
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
        if self.state.pair_blocked(ip):
            return self.error(429, "Too many failed attempts. Try again later.")
        if not token or not self.state.check_token(token, self.is_local):
            self.state.pair_failed(ip)
            return self.error(403, "Invalid or expired pairing link. Restart PhoneDrop on the computer "
                                   "and scan the new QR code.")
        self.state.pair_succeeded(ip)
        sid = self.state.new_session(ip, self.headers.get("User-Agent", ""))
        cookie = f"{SESSION_COOKIE}={sid}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Lax"
        if self.is_tls:
            cookie += "; Secure"
        self.log_message("paired new device: %s", self.headers.get("User-Agent", "?")[:80])
        # Redirect strips the token from the address bar / history.
        self.send_common(303, "text/plain", 0, {"Location": "/", "Set-Cookie": cookie, "Cache-Control": "no-store"})

    def do_list(self, wait):
        st = self.state
        if wait is not None and wait != "":
            deadline = time.time() + LONG_POLL_SECONDS
            while st.version() == wait and time.time() < deadline:
                time.sleep(0.4)
        self.send_json({"version": st.version(), "files": st.listing(), "notes": list(reversed(st.notes))})

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
        m = re.fullmatch(r"bytes=(\d*)-(\d*)", self.headers.get("Range", ""))
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
            paths = [p for p in (self.state.resolve(n) for n in names[:1000]) if p]
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

    def do_upload(self):
        st = self.state
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.error(411, "Content-Length required", close=True)
        if length <= 0:
            return self.error(400, "Empty file", close=True)
        if length > st.max_bytes:
            return self.error(413, f"File too large (max {human(st.max_bytes)})", close=True)
        if shutil.disk_usage(st.store).free < length + 256 * 1024 * 1024:
            return self.error(507, "Not enough disk space on the computer", close=True)

        raw = self.headers.get("X-Filename", "image")  # http.server decodes headers as latin-1
        orig = urllib.parse.unquote(raw.encode("latin-1", "replace").decode("utf-8", "replace"))[:255]
        tmp = st.partial / f"{secrets.token_hex(8)}.part"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
                stripped = strip_metadata(tmp, ext) if kind == "image" else strip_video(tmp, ext) if kind == "video" else False
            if stripped:
                length = tmp.stat().st_size
            stem = safe_stem(orig, kind)
            os.chmod(tmp, 0o644)
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
            self.log_message("received %s (%s%s)", final.name, human(length), ", " + meta if meta else "")
            if st.clipper and kind == "image":
                st.clipper.request(final.name)
            self.send_json({"name": final.name, "size": length}, 201)
        except (ConnectionError, TimeoutError, ssl.SSLError):
            self.close_connection = True
        finally:
            tmp.unlink(missing_ok=True)

    def do_thumb(self, name, size):
        p = self.state.resolve(name)
        size = int(size) if size.isdigit() and int(size) in THUMB_SIZES else THUMB_SIZES[0]
        t = self.state.thumbnail(p, size) if p else None
        if not t:
            return self.error(404, "No preview")
        data = t.read_bytes()
        self.send_common(200, "image/jpeg", len(data), {"Cache-Control": "private, max-age=604800"}, csp=FILE_CSP)
        self.wfile.write(data)

    def remove_file(self, name) -> bool:
        p = self.state.resolve(name)
        if not p:
            return False
        p.unlink()
        self.state.drop_thumbs(name)
        if self.state.clipper:
            self.state.clipper.forget(name)
        return True

    def do_delete(self, name):
        if not self.remove_file(name):
            return self.error(404, "Not found")
        self.send_json({"ok": True})

    def do_bulk_delete(self):
        body = self.read_json()
        names = body.get("names") if isinstance(body, dict) else None
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            return self.error(400, "Expected a list of file names")
        deleted = sum(self.remove_file(n) for n in names[:1000])
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


class TLSServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, addr, handler, ctx):
        self.ctx = ctx
        super().__init__(addr, handler)

    def get_request(self):
        sock, addr = self.socket.accept()
        # Handshake happens lazily in the worker thread, so a stalled client can't block accept().
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr


class PlainServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


# ---------------------------------------------------------------- TLS cert

def ensure_cert(ips):
    cert, key, meta = CONFIG_DIR / "cert.pem", CONFIG_DIR / "key.pem", CONFIG_DIR / "cert.json"
    want = sorted(set(ips) | {"127.0.0.1"})
    try:
        info = json.loads(meta.read_text())
        if set(want) <= set(info["ips"]) and info["expires"] > time.time() + 7 * 86400 and cert.exists() and key.exists():
            return cert, key
    except (OSError, ValueError, KeyError):
        pass
    san = ",".join([f"IP:{ip}" for ip in want] + ["DNS:localhost", f"DNS:{socket.gethostname()}.local"])
    days = 825
    print("Generating a new self-signed TLS certificate…")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", str(key), "-out", str(cert), "-days", str(days), "-subj", "/CN=PhoneDrop",
        "-addext", f"subjectAltName={san}", "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "extendedKeyUsage=serverAuth",
    ], check=True, capture_output=True)
    os.chmod(key, 0o600)
    meta.write_text(json.dumps({"ips": want, "expires": time.time() + days * 86400}))
    return cert, key


def cert_fingerprint(cert: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def print_qr(url):
    if shutil.which("qrencode"):
        subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "2", url])
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
    ap.add_argument("--keep-metadata", action="store_true",
                    help="don't strip EXIF/XMP metadata (GPS location, phone model…) from received images")
    ap.add_argument("--new-token", action="store_true", help="unpair all devices")
    ap.add_argument("--no-browser", action="store_true", help="don't open the panel in your browser")
    args = ap.parse_args()

    state = State(Path(args.dir).expanduser().resolve(), args.max_mb * 1024 * 1024, args.new_token,
                  args.pair_minutes, args.keep_metadata)
    if shutil.which("wl-copy") and (shutil.which("vips") or shutil.which("magick")):
        state.clipper = Clipper(state, max(1, args.clip_cache))
        state.clipper.scan()
    ips = lan_ips()
    ip = primary_ip()
    bind = args.bind or ip
    cert, key = ensure_cert(ips)

    hosts = {f"127.0.0.1:{args.local_port}", f"localhost:{args.local_port}",
             f"127.0.0.1:{args.port}", f"localhost:{args.port}",
             f"{socket.gethostname().lower()}.local:{args.port}"}
    hosts |= {f"{a}:{args.port}" for a in ips}
    Handler.state = state
    Handler.allowed_hosts = hosts

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)

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
    print(f"  Saving to:   {state.store}")
    print(f"  This PC:     http://127.0.0.1:{args.local_port}")
    print(f"  Phone:       https://{ip}:{args.port}   (same Wi-Fi)")
    print(f"  Cert SHA-256 {cert_fingerprint(cert)}")
    print("\n  Scan with your phone camera to pair (your browser will warn about the")
    print("  self-signed certificate once — check the fingerprint above and continue):\n")
    print_qr(phone_url)
    print("  Keep this QR private: anyone who scans it can upload to and read from the panel.")
    if state.pair_until:
        print(f"  Pairing is open until {time.strftime('%H:%M', time.localtime(state.pair_until))}; "
              "restart PhoneDrop to pair another device later.")
    print("  Run with --new-token to unpair every device.  Ctrl+C to stop.\n")
    if bind != "0.0.0.0" and not ipaddress.ip_address(bind).is_private:
        print(f"  WARNING: {bind} is not a private address. The phone port may be reachable from the internet.\n")

    if not args.no_browser and shutil.which("xdg-open"):
        subprocess.Popen(["xdg-open", pc_url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nStopping.")
        lan.shutdown()
        local.shutdown()


if __name__ == "__main__":
    main()
