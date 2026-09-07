"""Small, cache-only Lord Bio and guestbook service for the BitmapAds Beta site.

This module deliberately does not connect wallets or query external indexes on page
loads.  Ownership comes only from the already cached bitmap_registry table.
"""
import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import shutil
import sqlite3
import threading
import time
import unicodedata
from pathlib import Path

from config import M_ADDRESS
from moderation_policy import moderate as moderate_display_text

MAX_MESSAGE_CHARS = 140
PAGE_SIZE = 48
MAX_PAGE_SIZE = 72
COOKIE_NAME = "bitmapads_gbvid"
COOKIE_RE = re.compile(r"^[A-Za-z0-9_-]{20,80}\.[0-9a-f]{64}$")
_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = set()
_SECRET_LOCK = threading.Lock()
_SECRET_CACHE = {}


def _now():
    return int(time.time())


def _safe_number(value):
    try:
        number = int(value)
    except (ValueError, TypeError):
        return None
    return number if 0 <= number <= 999_999 else None


def _secret(secret_dir, filename="lord-bio-v1.secret"):
    """Return an on-server secret stored outside the web-served asset tree."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}\.secret", filename):
        raise ValueError("invalid secret filename")
    key = str(Path(secret_dir).resolve() / filename)
    with _SECRET_LOCK:
        cached = _SECRET_CACHE.get(key)
        if cached:
            return cached
        path = Path(secret_dir) / filename
        try:
            value = path.read_bytes()
            if len(value) < 32:
                raise OSError("short secret")
        except OSError:
            value = secrets.token_bytes(32)
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
            try:
                temporary.write_bytes(value)
                try:
                    os.chmod(temporary, 0o600)
                except OSError:
                    pass
                os.replace(temporary, path)
            finally:
                try:
                    temporary.unlink()
                except OSError:
                    pass
        _SECRET_CACHE[key] = value
        return value


def migrate_legacy_guestbook_secret(root, secret_dir):
    """Remove the retired guestbook secret from public storage without deleting it.

    The old file is moved into the private directory for a short operator recovery
    window. New guestbook tokens use a separate v2 secret and therefore cannot be
    forged with this retired value.
    """
    legacy = Path(root) / "storage" / "lord-bio-v1.secret"
    if not legacy.is_file():
        return False
    private = Path(secret_dir)
    private.mkdir(parents=True, exist_ok=True)
    target = private / ("retired-lord-bio-v1-" + str(_now()) + ".secret")
    try:
        # Hosting homes and the public document root can be separate mounts.
        # shutil.move safely falls back to copy-then-remove in that case.
        shutil.move(str(legacy), str(target))
        try:
            os.chmod(str(target), 0o600)
        except OSError:
            pass
        return True
    except OSError:
        return False


def _hash(secret, value):
    return hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _cookie_value(cookie_header, secret):
    for part in (cookie_header or "").split(";"):
        name, _, raw = part.strip().partition("=")
        if name != COOKIE_NAME or not COOKIE_RE.fullmatch(raw):
            continue
        visitor, signature = raw.rsplit(".", 1)
        if hmac.compare_digest(signature, _hash(secret, "cookie:" + visitor)):
            return visitor
    return None


def _visitor(cookie_header, secret, secure):
    existing = _cookie_value(cookie_header, secret)
    if existing:
        return existing, []
    visitor = secrets.token_urlsafe(24)
    value = visitor + "." + _hash(secret, "cookie:" + visitor)
    cookie = f"{COOKIE_NAME}={value}; Max-Age=2592000; Path=/; SameSite=Lax; HttpOnly"
    if secure:
        cookie += "; Secure"
    return visitor, [("Set-Cookie", cookie)]


def _masked_ip(value):
    """Public label only; the unmasked address is never stored or returned."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "network hidden"
    if address.version == 4:
        parts = str(address).split(".")
        return ".".join(parts[:3]) + ".*"
    groups = address.exploded.split(":")
    return ":".join(groups[:3]) + ":*"


def _message(value):
    if not isinstance(value, str):
        return None, "Write a message of up to 140 characters."
    normalized = unicodedata.normalize("NFKC", value)
    normalized = "".join(
        char for char in normalized
        if char in "\n\t" or unicodedata.category(char) not in {"Cc", "Cf", "Cs"}
    )
    normalized = "\n".join(" ".join(line.split()) for line in normalized.splitlines()).strip()
    if not normalized or len(normalized) > MAX_MESSAGE_CHARS:
        return None, "Write a message of 1 to 140 characters."
    rendered, _matches = moderate_display_text(normalized)
    rendered = rendered.strip()
    if not rendered:
        return None, "That message cannot be shown under the current community rules."
    return rendered, None


def _schema(con):
    key = str(con.execute("PRAGMA database_list").fetchone()[2])
    if key in _SCHEMA_READY:
        return
    with _SCHEMA_LOCK:
        if key in _SCHEMA_READY:
            return
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS lord_bio_profiles (
              lord_address TEXT PRIMARY KEY,
              display_name TEXT,
              bio TEXT,
              x_url TEXT,
              telegram_url TEXT,
              discord_url TEXT,
              website_url TEXT,
              updated_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS lord_bio_guestbook (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              lord_address TEXT NOT NULL,
              bitmap_number INTEGER NOT NULL,
              author_kind TEXT NOT NULL DEFAULT 'visitor',
              visitor_hash TEXT NOT NULL,
              ip_hash TEXT NOT NULL,
              visitor_label TEXT NOT NULL,
              text TEXT NOT NULL,
              text_hash TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              status TEXT NOT NULL DEFAULT 'visible'
            );
            CREATE INDEX IF NOT EXISTS idx_bitmap_registry_owner_number
              ON bitmap_registry(owner_address, bitmap_number);
            CREATE INDEX IF NOT EXISTS idx_lord_bio_messages
              ON lord_bio_guestbook(lord_address, status, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_lord_bio_rate
              ON lord_bio_guestbook(ip_hash, created_at DESC);
            CREATE TABLE IF NOT EXISTS lord_bio_challenges (
              nonce TEXT PRIMARY KEY,lord_address TEXT NOT NULL,bitmap_number INTEGER NOT NULL,
              origin TEXT NOT NULL,message TEXT NOT NULL,ip_hash TEXT NOT NULL,
              created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_bio_challenge_rate ON lord_bio_challenges(ip_hash,created_at);
            CREATE TABLE IF NOT EXISTS lord_bio_sessions (
              token_hash TEXT PRIMARY KEY,lord_address TEXT NOT NULL,origin TEXT NOT NULL,expires_at INTEGER NOT NULL,
              bitmap_number INTEGER NOT NULL DEFAULT -1
            );
            """
        )
        session_columns = {row[1] for row in con.execute("PRAGMA table_info(lord_bio_sessions)")}
        if "bitmap_number" not in session_columns:
            # -1 matches no Bitmap, so sessions predating the upgrade stop
            # authorising writes. They are thirty-minute tokens; users reconnect.
            con.execute("ALTER TABLE lord_bio_sessions ADD COLUMN bitmap_number INTEGER NOT NULL DEFAULT -1")
        columns = {row[1] for row in con.execute("PRAGMA table_info(lord_bio_profiles)")}
        if "avatar_number" not in columns:
            con.execute("ALTER TABLE lord_bio_profiles ADD COLUMN avatar_number INTEGER")
        if "avatar_url" not in columns:
            con.execute("ALTER TABLE lord_bio_profiles ADD COLUMN avatar_url TEXT")
        for name in ("tiktok_url", "instagram_url", "youtube_url", "gmgn_url"):
            if name not in columns:
                con.execute("ALTER TABLE lord_bio_profiles ADD COLUMN %s TEXT" % name)
        con.commit()
        _SCHEMA_READY.add(key)


def _has_claim_numbers(con):
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='satflow_center_claims'"
    ).fetchone()
    return bool(row)


def _profile(row, bitmap_number):
    name = (row["display_name"] or "").strip() if row else ""
    bio = (row["bio"] or "").strip() if row else ""
    return {
        "name": name or f"Lord of {bitmap_number}.bitmap",
        "bio": bio or "This Lord has not written a bio yet.",
        "avatar_number": row["avatar_number"] if row else None,
        "avatar_url": (row["avatar_url"] or "") if row else "",
        "social": {
            "x": (row["x_url"] or "") if row else "",
            "telegram": (row["telegram_url"] or "") if row else "",
            "discord": (row["discord_url"] or "") if row else "",
            "website": (row["website_url"] or "") if row else "",
            "tiktok": (row["tiktok_url"] or "") if row else "",
            "instagram": (row["instagram_url"] or "") if row else "",
            "youtube": (row["youtube_url"] or "") if row else "",
            "gmgn": (row["gmgn_url"] or "") if row else "",
        },
    }


def get_bio(db_path, bitmap_number, page=0, sort="bitmap"):
    number = _safe_number(bitmap_number)
    if number is None:
        return 400, {"ok": False, "error": "Invalid Bitmap number."}
    try:
        page = max(0, int(page))
    except (ValueError, TypeError):
        page = 0
    sort = "inscription" if sort == "inscription" else "bitmap"
    con = sqlite3.connect(str(db_path), timeout=5)
    con.row_factory = sqlite3.Row
    try:
        _schema(con)
        parcel = con.execute(
            "SELECT bitmap_number, owner_address, updated_at FROM bitmap_registry WHERE bitmap_number=?",
            (number,),
        ).fetchone()
        if not parcel or not parcel["owner_address"]:
            return 404, {"ok": False, "error": "No cached Lord record is available for this Bitmap yet."}
        lord = parcel["owner_address"]
        if lord == M_ADDRESS:
            return 403, {"ok": False, "error": "Lord Bio is not available for the Merlin Chain address during Beta."}
        profile_row = con.execute(
            "SELECT * FROM lord_bio_profiles WHERE lord_address=?", (lord,)
        ).fetchone()
        total = int(
            con.execute("SELECT COUNT(*) FROM bitmap_registry WHERE owner_address=?", (lord,)).fetchone()[0]
        )
        offset = min(page * PAGE_SIZE, max(0, total - 1))
        claims = _has_claim_numbers(con)
        if claims:
            if sort == "inscription":
                order = "CASE WHEN c.inscription_number IS NULL THEN 1 ELSE 0 END, c.inscription_number ASC, r.bitmap_number ASC"
            else:
                order = "r.bitmap_number ASC"
            rows = con.execute(
                f"""
                SELECT r.bitmap_number, r.bitmap_inscription_id, c.inscription_number
                FROM bitmap_registry r
                LEFT JOIN (
                  SELECT bitmap_number, MAX(inscription_number) AS inscription_number
                  FROM satflow_center_claims
                  WHERE bitmap_number IN (
                    SELECT bitmap_number FROM bitmap_registry WHERE owner_address=?
                  )
                  GROUP BY bitmap_number
                ) c ON c.bitmap_number=r.bitmap_number
                WHERE r.owner_address=? ORDER BY {order} LIMIT ? OFFSET ?
                """,
                (lord, lord, PAGE_SIZE, offset),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT bitmap_number, bitmap_inscription_id, NULL AS inscription_number FROM bitmap_registry WHERE owner_address=? ORDER BY bitmap_number ASC LIMIT ? OFFSET ?",
                (lord, PAGE_SIZE, offset),
            ).fetchall()
        holdings = [
            {
                "bitmap_number": int(item["bitmap_number"]),
                "inscription_number": item["inscription_number"],
                "bitmap_inscription_id": item["bitmap_inscription_id"],
            }
            for item in rows
        ]
        return 200, {
            "ok": True,
            "bitmap_number": number,
            "lord": lord,
            "ownership_source": "cached Bitmap registry",
            "ownership_updated_at": parcel["updated_at"],
            "profile": _profile(profile_row, number),
            "collections": {"bitmap": total, "nft": "coming_soon", "names": "coming_soon"},
            "holdings": holdings,
            "pagination": {"page": page, "page_size": PAGE_SIZE, "total": total, "has_more": offset + len(holdings) < total},
            "inscription_number_cache": claims,
            "sort": sort,
        }
    except sqlite3.Error:
        return 503, {"ok": False, "error": "Lord Bio data is temporarily unavailable."}
    finally:
        con.close()


def guestbook_preview(db_path, bitmap_number):
    """Only three public notes; no holdings scan, session cookie or remote calls."""
    number = _safe_number(bitmap_number)
    if number is None:
        return 400, {"ok": False, "error": "Invalid Bitmap number."}
    con = sqlite3.connect(str(db_path), timeout=1)
    con.row_factory = sqlite3.Row
    try:
        _schema(con)
        parcel = con.execute("SELECT owner_address FROM bitmap_registry WHERE bitmap_number=?", (number,)).fetchone()
        lord = parcel["owner_address"] if parcel else None
        messages = []
        if lord and lord != M_ADDRESS:
            rows = con.execute(
                "SELECT author_kind,text,created_at FROM lord_bio_guestbook "
                "WHERE lord_address=? AND status='visible' ORDER BY created_at DESC,id DESC LIMIT 3",
                (lord,),
            ).fetchall()
            for row in rows:
                text, _error = _message(row["text"])
                if text:
                    messages.append({"author_kind": row["author_kind"], "text": text, "created_at": row["created_at"]})
        return 200, {"ok": True, "bitmap_number": number, "messages": messages}
    except sqlite3.Error:
        return 503, {"ok": False, "error": "Public notes are temporarily unavailable."}
    finally:
        con.close()


def guestbook_latest(db_path, limit=10):
    """Return a small cached global feed; stale-owner messages are excluded."""
    try:
        limit = min(10, max(1, int(limit)))
    except (TypeError, ValueError):
        limit = 10
    con = sqlite3.connect(str(db_path), timeout=2)
    con.row_factory = sqlite3.Row
    try:
        _schema(con)
        rows = con.execute(
            "SELECT g.bitmap_number,g.author_kind,g.text,g.created_at "
            "FROM lord_bio_guestbook g JOIN bitmap_registry r "
            "ON r.bitmap_number=g.bitmap_number AND r.owner_address=g.lord_address "
            "WHERE g.status='visible' AND g.lord_address<>? "
            "ORDER BY g.created_at DESC,g.id DESC LIMIT ?",
            (M_ADDRESS, limit),
        ).fetchall()
        messages = []
        for row in rows:
            text, _error = _message(row["text"])
            if text:
                messages.append({"bitmap_number": int(row["bitmap_number"]),
                                 "author_kind": "lord" if row["author_kind"] == "lord" else "visitor",
                                 "text": text, "created_at": int(row["created_at"])})
        return 200, {"ok": True, "messages": messages}
    except sqlite3.Error:
        return 503, {"ok": False, "error": "Public notes are temporarily unavailable."}
    finally:
        con.close()


def _token(secret, lord, visitor, issued):
    payload = f"{issued}:{lord}:{visitor}"
    signature = _hash(secret, "guest:" + payload)
    return base64.urlsafe_b64encode(f"{issued}.{signature}".encode()).decode().rstrip("=")


def _valid_token(secret, value, lord, visitor):
    if not isinstance(value, str) or len(value) > 180:
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode()
        issued_raw, signature = raw.split(".", 1)
        issued = int(issued_raw)
    except (ValueError, UnicodeDecodeError):
        return False
    now = _now()
    return now - 7200 <= issued <= now - 3 and hmac.compare_digest(
        signature, _hash(secret, f"guest:{issued}:{lord}:{visitor}")
    )


def guestbook_get(db_path, secret_dir, bitmap_number, cookie_header="", remote_ip="", secure=True):
    code, bio = get_bio(db_path, bitmap_number)
    if code != 200:
        return code, bio, []
    secret = _secret(secret_dir, "lord-bio-guestbook-v2.secret")
    visitor, headers = _visitor(cookie_header, secret, secure)
    con = sqlite3.connect(str(db_path), timeout=5)
    con.row_factory = sqlite3.Row
    try:
        _schema(con)
        rows = con.execute(
            "SELECT author_kind, visitor_label, text, created_at FROM lord_bio_guestbook WHERE lord_address=? AND status='visible' ORDER BY created_at DESC, id DESC LIMIT 60",
            (bio["lord"],),
        ).fetchall()
        messages = [
            {
                "author_kind": row["author_kind"] if row["author_kind"] == "lord" else "visitor",
                "visitor_label": "Lord" if row["author_kind"] == "lord" else row["visitor_label"],
                "text": row["text"],
                "created_at": int(row["created_at"]),
            }
            for row in rows
        ]
        now = _now()
        return 200, {
            "ok": True,
            "messages": messages,
            "guest_token": _token(secret, bio["lord"], visitor, now),
            "not_before": now + 3,
            "privacy": "A masked network label is public. Raw IP addresses are neither shown nor stored.",
        }, headers
    except sqlite3.Error:
        return 503, {"ok": False, "error": "Guestbook is temporarily unavailable."}, headers
    finally:
        con.close()


def guestbook_post(db_path, secret_dir, bitmap_number, payload, cookie_header="", remote_ip="", secure=True, authenticated_lord=None):
    code, bio = get_bio(db_path, bitmap_number)
    if code != 200:
        return code, bio, []
    if not isinstance(payload, dict):
        return 400, {"ok": False, "error": "Invalid message request."}, []
    if str(payload.get("company") or "").strip():
        return 400, {"ok": False, "error": "Message could not be accepted."}, []
    secret = _secret(secret_dir, "lord-bio-guestbook-v2.secret")
    visitor, headers = _visitor(cookie_header, secret, secure)
    if not _valid_token(secret, payload.get("guest_token"), bio["lord"], visitor):
        return 429, {"ok": False, "error": "Please wait a moment, then try again."}, headers
    text, error = _message(payload.get("text"))
    if error:
        return 400, {"ok": False, "error": error}, headers
    ip_value = remote_ip or "unknown"
    ip_hash = _hash(secret, "ip:" + ip_value)
    visitor_hash = _hash(secret, "visitor:" + visitor)
    text_hash = _hash(secret, "text:" + text)
    now = _now()
    con = sqlite3.connect(str(db_path), timeout=5)
    con.row_factory = sqlite3.Row
    try:
        _schema(con)
        con.execute("BEGIN IMMEDIATE")
        current = con.execute("SELECT owner_address FROM bitmap_registry WHERE bitmap_number=?",(int(bio["bitmap_number"]),)).fetchone()
        if not current or current[0] != bio["lord"]:
            return 409,{"ok":False,"error":"The Bitmap changed owner. Please reload."},headers
        author = "lord" if authenticated_lord and authenticated_lord == current[0] else "visitor"
        recent = con.execute(
            "SELECT MAX(created_at) FROM lord_bio_guestbook WHERE lord_address=? AND ip_hash=? AND author_kind=?",
            (bio["lord"], ip_hash,author),
        ).fetchone()[0]
        if recent and now - int(recent) < (20 if author=="lord" else 20 * 60):
            return 429, {"ok": False, "error": "Please wait 20 seconds before posting again." if author=="lord" else "Please wait 20 minutes before posting another note here."}, headers
        daily = int(con.execute(
            "SELECT COUNT(*) FROM lord_bio_guestbook WHERE ip_hash=? AND created_at>? AND author_kind='visitor'",
            (ip_hash, now - 24 * 60 * 60),
        ).fetchone()[0])
        if author=="visitor" and daily >= 5:
            return 429, {"ok": False, "error": "This network has reached today’s guestbook limit."}, headers
        duplicate = con.execute(
            "SELECT 1 FROM lord_bio_guestbook WHERE lord_address=? AND visitor_hash=? AND text_hash=? AND created_at>? LIMIT 1",
            (bio["lord"], visitor_hash, text_hash, now - 30 * 24 * 60 * 60),
        ).fetchone()
        if duplicate:
            return 409, {"ok": False, "error": "That note was already posted here."}, headers
        label = _masked_ip(ip_value)
        con.execute(
            "INSERT INTO lord_bio_guestbook(lord_address,bitmap_number,author_kind,visitor_hash,ip_hash,visitor_label,text,text_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (bio["lord"], int(bio["bitmap_number"]), author, visitor_hash, ip_hash, label, text, text_hash, now),
        )
        con.commit()
        return 200, {
            "ok": True,
            "message": {"author_kind": author, "visitor_label": label, "text": text, "created_at": now},
            "guest_token": _token(secret, bio["lord"], visitor, now),
            "not_before": now + 3,
        }, headers
    except sqlite3.Error:
        return 503, {"ok": False, "error": "Guestbook could not save that note. Please try again."}, headers
    finally:
        con.close()
