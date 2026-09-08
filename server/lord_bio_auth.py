"""Short-lived, origin-bound wallet sessions for cached-owner Bio editing.

No session in localStorage, no private keys, no transaction API. All ownership
decisions use the existing registry (not live chain claims). Python 3.6+.
"""
import hashlib
import os
import re
import secrets
import sqlite3
import time
from urllib.parse import urlsplit

import bio_signature
import lord_bio
from inscription_assets import AssetError, private_directory
from moderation_policy import moderate

ASSET_LOOKUPS_PER_DAY = 25

ALLOWED_ORIGINS = {"https://bitmap.bio", "https://bitmapads.com", "https://www.bitmap.bio", "https://www.bitmapads.com"}

def _origin(value):
    if value in ALLOWED_ORIGINS: return value
    if os.environ.get("BITMAPADS_DEV_ORIGINS") == "1" and re.fullmatch(r"http://(127\.0\.0\.1|localhost):[0-9]{2,5}", value or ""): return value
    raise ValueError("Open this page directly on bitmap.bio or bitmapads.com.")

def _hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def _db(path):
    con = sqlite3.connect(str(path), timeout=5)
    con.row_factory = sqlite3.Row
    lord_bio._schema(con)
    return con

def _owner(con, number):
    row = con.execute("SELECT owner_address FROM bitmap_registry WHERE bitmap_number=?", (number,)).fetchone()
    owner = row[0] if row else None
    if not owner or owner == lord_bio.M_ADDRESS: raise ValueError("No editable Lord profile is available for this Bitmap.")
    return owner

def _session(con, number, authorization, origin):
    if not isinstance(authorization,str) or not re.fullmatch(r"Bearer [A-Za-z0-9_-]{40,64}",authorization):
        raise PermissionError("Connect your wallet and verify ownership before editing.")
    row = con.execute("SELECT lord_address FROM lord_bio_sessions WHERE token_hash=? AND origin=? AND bitmap_number=? AND expires_at>?",
                      (_hash(authorization[7:]), _origin(origin), number, int(time.time()))).fetchone()
    owner = _owner(con, number)
    if not row or row[0] != owner: raise PermissionError("Your editing session expired or the Bitmap changed owner. Please reconnect.")
    return owner

def verified_owner(db_path, number, authorization, origin):
    con = _db(db_path)
    try: return _session(con, number, authorization, origin)
    except (ValueError,PermissionError): return None
    finally: con.close()

def _clean(value, maximum):
    if not isinstance(value,str) or len(value) > maximum: raise ValueError("Profile text is too long.")
    if any(ord(c)<32 and c not in "\n\t" for c in value): raise ValueError("Unsupported profile characters.")
    return moderate(value.strip())[0].strip()

def _social(kind, value):
    value = str(value or "").strip()
    if not value: return ""
    if len(value)>300 or any(ord(c)<33 for c in value): raise ValueError("Enter a valid HTTPS social link.")
    u = urlsplit(value)
    hosts = {"x": ("x.com","twitter.com"), "telegram": ("t.me","telegram.me"), "discord": ("discord.gg","discord.com"),
             "tiktok": ("tiktok.com","www.tiktok.com"), "instagram": ("instagram.com","www.instagram.com"),
             "youtube": ("youtube.com","www.youtube.com","youtu.be"), "gmgn": ("gmgn.ai","www.gmgn.ai")}
    if u.scheme != "https" or not u.hostname or u.username or u.password or u.port not in (None,443):
        raise ValueError("Social links must use HTTPS without a username or password.")
    if kind in hosts and u.hostname.lower() not in hosts[kind]: raise ValueError("Use the official " + kind + " website for this link.")
    return value

def handle(root, db_path, storage_dir, number, action, payload, origin, authorization="", remote_ip="", resolver=None):
    """POST-only actions. Caller enforces bounded UTF-8 JSON request size."""
    con = None
    try:
        if not (private_directory(root) / "bio-wallet-ready-v1").is_file():
            return 503, {"ok":False,"error":"Wallet editing is awaiting the server initialization step. Please contact the site operator."}
        origin = _origin(origin)
        number = lord_bio._safe_number(number)
        if number is None or not isinstance(payload,dict): raise ValueError("Invalid profile request.")
        con = _db(db_path)
        now = int(time.time())
        if action == "logout":
            if isinstance(authorization,str) and re.fullmatch(r"Bearer [A-Za-z0-9_-]{40,64}",authorization):
                con.execute("BEGIN IMMEDIATE")
                con.execute("DELETE FROM lord_bio_sessions WHERE token_hash=?",(_hash(authorization[7:]),))
                con.commit()
            return 200, {"ok":True}
        owner = _owner(con, number)
        if action == "challenge":
            if payload.get("address") != owner: raise PermissionError("The connected address does not own this Bitmap in our cached registry.")
            try: bio_signature.address_program(owner)
            except ValueError: raise ValueError("This Beta supports native Bitcoin SegWit (bc1q) and Taproot (bc1p) single-key wallets only.")
            secret = lord_bio._secret(private_directory(root), "lord-bio-wallet-auth-v2.secret")
            network = lord_bio._hash(secret, "bio-login:" + str(remote_ip))
            con.execute("BEGIN IMMEDIATE")
            if con.execute("SELECT COUNT(*) FROM lord_bio_challenges WHERE ip_hash=? AND created_at>?", (network,now-600)).fetchone()[0] >= 20:
                return 429, {"ok":False,"error":"Too many wallet attempts. Please wait ten minutes."}
            nonce = secrets.token_urlsafe(24)
            message = (origin + " requests a Bitmap Lord Bio sign-in.\n\nAddress: " + owner +
                       "\nBitmap: " + str(number) + ".bitmap\n\nThis signature only allows editing your public Bio and posting as Lord.\nNo Bitcoin transfer. No transaction. No spending permission.\n" +
                       "\nURI: " + origin + "/" + str(number) + "\nNonce: " + nonce +
                       "\nIssued at (Unix): " + str(now) + "\nExpires at (Unix): " + str(now+300))
            con.execute("INSERT INTO lord_bio_challenges VALUES(?,?,?,?,?,?,?,?,0)", (nonce,owner,number,origin,message,network,now,now+300))
            # Expired authentication material only; no user content is removed.
            con.execute("DELETE FROM lord_bio_challenges WHERE created_at<?", (now-86400,))
            con.execute("DELETE FROM lord_bio_sessions WHERE expires_at<?", (now-86400,))
            con.commit()
            return 200, {"ok":True,"nonce":nonce,"message":message,"address":owner,"expires_at":now+300}
        if action == "verify":
            nonce = payload.get("nonce")
            if not isinstance(nonce,str) or len(nonce)>64: raise ValueError("Invalid wallet challenge.")
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT * FROM lord_bio_challenges WHERE nonce=? AND origin=? AND bitmap_number=? AND expires_at>? AND used=0", (nonce,origin,number,now)).fetchone()
            if not row or row["lord_address"] != owner: raise PermissionError("Wallet challenge expired or was already used. Connect again.")
            con.execute("UPDATE lord_bio_challenges SET used=1 WHERE nonce=?", (nonce,))
            con.commit()  # one attempt per challenge, including failed signatures
            if not bio_signature.verify(owner,row["message"],payload.get("signature")):
                raise PermissionError("Wallet signature could not be verified. Please reconnect using the owning address.")
            con.execute("BEGIN IMMEDIATE")
            if _owner(con,number) != owner: raise PermissionError("The Bitmap changed owner. Please reload.")
            token = secrets.token_urlsafe(32)
            con.execute("INSERT INTO lord_bio_sessions(token_hash,lord_address,origin,expires_at,bitmap_number) VALUES(?,?,?,?,?)",(_hash(token),owner,origin,now+1800,number))
            con.commit()
            return 200, {"ok":True,"token":token,"lord":owner,"bitmap":number,"expires_at":now+1800}
        if action in ("save","avatar"):
            owner = _session(con,number,authorization,origin)
            avatar_number = payload.get("avatar_number", "")
            if not isinstance(avatar_number,(str,int)) or isinstance(avatar_number,bool): raise ValueError("Enter a valid inscription number.")
            avatar_number = str(avatar_number).strip()
            if avatar_number and not re.fullmatch(r"-?[0-9]{1,12}",avatar_number): raise ValueError("Enter a valid inscription number, not an ID or URL.")
            if action=="avatar" and not avatar_number: raise ValueError("Enter an image inscription number.")
            if action == "save":
                previous = con.execute("SELECT updated_at FROM lord_bio_profiles WHERE lord_address=?",(owner,)).fetchone()
                if previous and now-int(previous[0])<5:
                    return 429, {"ok":False,"error":"Please wait a few seconds before saving again."}
            asset = None
            if avatar_number:
                if resolver is None: raise ValueError("Image lookup is temporarily unavailable.")
                con.execute("BEGIN IMMEDIATE")
                con.execute("DELETE FROM lord_bio_asset_lookups WHERE created_at<?", (now-86400,))
                spent = con.execute("SELECT COUNT(*) FROM lord_bio_asset_lookups WHERE lord_address=? AND created_at>?", (owner,now-86400)).fetchone()[0]
                if spent >= ASSET_LOOKUPS_PER_DAY:
                    con.commit()
                    return 429, {"ok":False,"error":"You have reached today's image lookup limit. Please try again tomorrow."}
                con.execute("INSERT INTO lord_bio_asset_lookups VALUES(?,?)", (owner,now))
                con.commit()
                asset = resolver(avatar_number)
                if not isinstance(asset,dict) or not re.fullmatch(r"/storage/ads/offline/[A-Za-z0-9_.-]+",asset.get("asset_url","")):
                    raise ValueError("A local static image is required.")
            if action=="avatar": return 200, {"ok":True,"asset":asset}
            name,bio = _clean(payload.get("name",""),60),_clean(payload.get("bio",""),500)
            social = payload.get("social") or {}
            if not isinstance(social,dict): raise ValueError("Invalid social links.")
            links = [_social(k,social.get(k)) for k in ("x","telegram","discord","website","tiktok","instagram","youtube","gmgn")]
            con.execute("BEGIN IMMEDIATE")
            owner = _session(con,number,authorization,origin)  # check again after image lookup
            con.execute("INSERT OR REPLACE INTO lord_bio_profiles(lord_address,display_name,bio,x_url,telegram_url,discord_url,website_url,tiktok_url,instagram_url,youtube_url,gmgn_url,updated_at,avatar_number,avatar_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (owner,name,bio)+tuple(links)+(int(time.time()),int(avatar_number) if avatar_number else None,asset["asset_url"] if asset else None))
            con.commit()
            return 200, {"ok":True,"profile":lord_bio._profile(con.execute("SELECT * FROM lord_bio_profiles WHERE lord_address=?",(owner,)).fetchone(),number)}
        return 404, {"ok":False,"error":"Not found."}
    except PermissionError as error:
        return 403, {"ok":False,"error":str(error)}
    except (ValueError,AssetError) as error:
        return 400, {"ok":False,"error":str(error)}
    except sqlite3.Error:
        return 503, {"ok":False,"error":"Profile service is temporarily unavailable. Please retry."}
    finally:
        if con is not None: con.close()
