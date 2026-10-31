#!/usr/bin/env python3
"""PhoneDrop — send images from your phone to this computer over the local network.

Two listeners:
  * HTTPS on the LAN (default :8443) for the phone (self-signed cert, generated on first run)
  * HTTP on 127.0.0.1 (default :8080) for this computer's browser (localhost is a secure
    context, so clipboard copy works without certificate warnings)

Access requires pairing: scan the QR code printed in the terminal. Pairing sets a
long-lived HttpOnly session cookie. Run with --new-token to revoke every paired device.
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

MIME = {
    "jpg": "image/jpeg", "png": "image/png", "gif": "image/gif", "webp": "image/webp",
    "heic": "image/heic", "avif": "image/avif", "bmp": "image/bmp", "tiff": "image/tiff",
}
STATIC_FILES = {
    "app.js": "text/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
    "icon.svg": "image/svg+xml",
}
THUMB_SIZES = (480, 1600)  # grid, and the viewer for formats browsers can't display (HEIC/TIFF)
GENERIC_STEMS = {"image", "photo", "img", "file", "blob", "picture", "upload"}

PAGE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; "
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


def safe_stem(name: str) -> str:
    name = unicodedata.normalize("NFKC", name).replace("\\", "/").rsplit("/", 1)[-1]
    stem = name.rsplit(".", 1)[0] if "." in name else name
    stem = re.sub(r"[^\w\- ()]+", "_", stem, flags=re.UNICODE).strip(" ._-")[:80]
    if not stem or stem.lower() in GENERIC_STEMS:
        stem = time.strftime("IMG_%Y%m%d_%H%M%S")
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
    def __init__(self, store: Path, max_bytes: int, new_token: bool):
        self.store = store
        self.partial = store / ".partial"
        self.thumbs = store / ".thumbs"
        self.thumb_locks = {}
        self.thumb_slots = threading.BoundedSemaphore(2)  # cap concurrent decoders
        self.max_bytes = max_bytes
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

        self.token_file = CONFIG_DIR / "token"
        self.sessions_file = CONFIG_DIR / "sessions.json"
        if new_token or not self.token_file.exists():
            self._write_private(self.token_file, secrets.token_urlsafe(32))
            self._write_private(self.sessions_file, "{}")
        self.token = self.token_file.read_text().strip()
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

    def check_token(self, t: str) -> bool:
        return hmac.compare_digest(t.encode(), self.token.encode())

    # ---- files

    def version(self) -> str:
        return str(self.store.stat().st_mtime_ns)

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
            files.append({"name": p.name, "size": st.st_size, "mtime": st.st_mtime, "type": MIME[ext],
                          "url": f"/f/{q}?v={st.st_mtime_ns}", "thumb": f"/t/{q}?v={st.st_mtime_ns}"})
        files.sort(key=lambda f: f["mtime"], reverse=True)
        return files


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
                                       "serverCopy": self.is_local and bool(shutil.which("wl-copy")),
                                       "folder": str(self.state.store) if self.is_local else None})
            if path == "/api/files":
                return self.do_list(query.get("wait", [None])[0])
            if path == "/api/zip":
                return self.do_zip()
            if path.startswith("/t/"):
                return self.do_thumb(name, query.get("size", ["480"])[0])
            if path.startswith("/f/"):
                return self.do_file(name, query.get("dl", ["0"])[0] == "1")
        elif method == "POST":
            if path == "/api/upload":
                return self.do_upload()
            if path.startswith("/api/copy/"):
                return self.do_copy(name)
            if path == "/api/open-folder":
                return self.do_open_folder()
            if path == "/api/logout":
                self.state.drop_session(self.cookie(SESSION_COOKIE))
                return self.send_json({"ok": True}, extra={"Set-Cookie": f"{SESSION_COOKIE}=; Path=/; Max-Age=0"})
        elif method == "DELETE":
            if path.startswith("/api/files/"):
                return self.do_delete(name)
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
        if not token or not self.state.check_token(token):
            self.state.pair_failed(ip)
            return self.error(403, "Invalid or expired pairing link. Scan the QR code again.")
        self.state.fails.pop(ip, None)
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
        self.send_json({"version": st.version(), "files": st.listing()})

    def do_file(self, name, download):
        p = self.state.resolve(name)
        if not p:
            return self.error(404, "Not found")
        size = p.stat().st_size
        disp = "attachment" if download else "inline"
        quoted = urllib.parse.quote(p.name)
        self.send_common(200, MIME[p.suffix[1:].lower()], size, {
            "Content-Disposition": f"{disp}; filename*=UTF-8''{quoted}",
            "Cache-Control": "private, max-age=86400",
        }, csp=FILE_CSP)
        with open(p, "rb") as f:
            shutil.copyfileobj(f, self.wfile, 256 * 1024)

    def do_zip(self):
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
            for f in self.state.listing():
                p = self.state.resolve(f["name"])
                if p:
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
                    if len(head) < 64:
                        head += chunk[:64 - len(head)]
                    out.write(chunk)
                    remaining -= len(chunk)
            ext = sniff_image(head)
            if not ext:
                tmp.unlink(missing_ok=True)
                return self.error(415, "That file is not a supported image")

            stem = safe_stem(orig)
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
            self.log_message("received %s (%s)", final.name, human(length))
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

    def do_delete(self, name):
        p = self.state.resolve(name)
        if not p:
            return self.error(404, "Not found")
        p.unlink()
        self.state.drop_thumbs(name)
        self.send_json({"ok": True})

    def do_copy(self, name):
        if not self.is_local or not shutil.which("wl-copy"):
            return self.error(403, "Server-side copy is only available on this computer")
        p = self.state.resolve(name)
        if not p:
            return self.error(404, "Not found")
        with open(p, "rb") as f:
            r = subprocess.run(["wl-copy", "--type", MIME[p.suffix[1:].lower()]], stdin=f,
                               capture_output=True, timeout=10)
        if r.returncode:
            return self.error(500, "wl-copy failed: " + r.stderr.decode(errors="replace")[:200])
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
    ap = argparse.ArgumentParser(description="Receive images from your phone over the local network.")
    ap.add_argument("--port", type=int, default=8443, help="HTTPS port for the phone (default 8443)")
    ap.add_argument("--local-port", type=int, default=8080, help="localhost HTTP port for this computer (default 8080)")
    ap.add_argument("--bind", default="0.0.0.0", help="address for the LAN listener (default all interfaces)")
    ap.add_argument("--dir", default=str(Path.home() / "Pictures" / "PhoneDrop"), help="where images are saved")
    ap.add_argument("--max-mb", type=int, default=200, help="max size per file in MB (default 200)")
    ap.add_argument("--new-token", action="store_true", help="rotate the pairing token and unpair all devices")
    ap.add_argument("--no-browser", action="store_true", help="don't open the panel in your browser")
    args = ap.parse_args()

    state = State(Path(args.dir).expanduser().resolve(), args.max_mb * 1024 * 1024, args.new_token)
    ips = lan_ips()
    ip = primary_ip()
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
        lan = TLSServer((args.bind, args.port), Handler, ctx)
        local = PlainServer(("127.0.0.1", args.local_port), Handler)
    except OSError as e:
        sys.exit(f"Could not start server: {e}  (is PhoneDrop already running? try --port / --local-port)")

    for srv in (lan, local):
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    phone_url = f"https://{ip}:{args.port}/pair?t={state.token}"
    pc_url = f"http://127.0.0.1:{args.local_port}/pair?t={state.token}"

    print("\n  PhoneDrop is running")
    print(f"  Saving to:   {state.store}")
    print(f"  This PC:     http://127.0.0.1:{args.local_port}")
    print(f"  Phone:       https://{ip}:{args.port}   (same Wi-Fi)")
    print(f"  Cert SHA-256 {cert_fingerprint(cert)}")
    print("\n  Scan with your phone camera to pair (your browser will warn about the")
    print("  self-signed certificate once — check the fingerprint above and continue):\n")
    print_qr(phone_url)
    print("  Keep this QR private: anyone who scans it can upload to and read from the panel.")
    print("  Run with --new-token to unpair every device.  Ctrl+C to stop.\n")

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
