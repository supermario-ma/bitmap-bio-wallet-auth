"""Bounded, cached Ordiscan image lookup. Compatible with cPanel Python 3.6+.

Only the server contacts Ordiscan. No remote URLs or credentials are returned
to browsers. Metadata and quota bookkeeping are private; cached pixels public.
"""
import hashlib
import io
import json
import logging
import os
import re
import sqlite3
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ID = re.compile(r'^[0-9a-f]{64}i[0-9]+$', re.I)
NUMBER = re.compile(r'^-?[0-9]{1,12}$')
MAX_SOURCE = 4 * 1024 * 1024
MAX_CACHE = 96 * 1024
SIDE = 256
ERRORS = {
    'invalid':'Enter a valid inscription number.',
    'key':'Image lookup is not configured. Please contact the site operator.',
    'auth':'Ordiscan rejected the API key. Please contact the site operator.',
    'quota':'Image lookup is temporarily rate limited. Please try again later.',
    'missing':'Inscription not found. Check the number and try again.',
    'type':'This inscription is not an image. Please choose an image inscription.',
    'upstream':'The image service is temporarily unavailable. Please try again.',
    'static':'No static preview is available for this inscription yet.',
    'busy':'Image lookup is busy. Please try again shortly.',
}

class AssetError(Exception):
    def __init__(self, code):
        self.code=code
        super().__init__(ERRORS[code])

def require_image_metadata(meta, allow_unknown=False):
    """Reject non-image inscriptions before downloading or reusing a preview.

    Empty metadata may be followed through a delegate, but an explicit HTML,
    model, JSON, audio or video declaration is never a request to render it.
    """
    kind=str((meta or {}).get('content_type') or '').split(';',1)[0].strip().lower()
    if not kind and allow_unknown:return
    if not kind.startswith('image/'):raise AssetError('type')

def private_directory(root):
    configured=os.environ.get('BITMAPADS_PRIVATE_DIR')
    if configured:return Path(configured)
    return Path(root)/'.private' if os.name=='nt' else Path.home()/'bitmapads_private'

def read_key(root):
    direct=os.environ.get('BITMAPADS_ORDISCAN_KEY','').strip()
    if direct:return direct
    path=Path(os.environ.get('BITMAPADS_ORDISCAN_KEY_FILE',str(private_directory(root)/'ordiscan_api_key')))
    try:return path.read_text(encoding='utf-8').strip()
    except OSError:return ''

class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old=urllib.parse.urlsplit(req.full_url);new=urllib.parse.urlsplit(newurl)
        if new.scheme!='https' or new.hostname!=old.hostname:raise AssetError('upstream')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def download(url, maximum, key=None, timeout=12):
    headers={'User-Agent':'BitmapAds/0.1','Accept':'application/json' if key else 'image/*'}
    if key:headers['Authorization']='Bearer '+key
    req=urllib.request.Request(url,headers=headers)
    with urllib.request.build_opener(SafeRedirect()).open(req,timeout=timeout) as response:
        if int(response.headers.get('Content-Length','0'))>maximum:raise AssetError('static')
        data=response.read(maximum+1)
        if not data or len(data)>maximum:raise AssetError('static')
        return data

def raster_info(data):
    """Validate static PNG/WebP containers even on hosts without Pillow."""
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        pos=8;size=None;ended=False
        while pos+12<=len(data):
            length=struct.unpack('>I',data[pos:pos+4])[0];kind=data[pos+4:pos+8]
            if pos+length+12>len(data):raise AssetError('static')
            if kind==b'IHDR':
                if length!=13:raise AssetError('static')
                size=struct.unpack('>II',data[pos+8:pos+16])
            if kind in (b'acTL',b'fcTL',b'fdAT'):raise AssetError('static')
            if kind==b'IEND':ended=True;break
            pos+=length+12
        if size and ended:return 'png',size[0],size[1]
    if len(data)>=30 and data[:4]==b'RIFF' and data[8:12]==b'WEBP':
        if struct.unpack('<I',data[4:8])[0]+8!=len(data):raise AssetError('static')
        pos=12;size=None
        while pos+8<=len(data):
            kind=data[pos:pos+4];length=struct.unpack('<I',data[pos+4:pos+8])[0];body=data[pos+8:pos+8+length]
            if len(body)!=length:raise AssetError('static')
            if kind in (b'ANIM',b'ANMF'):raise AssetError('static')
            if kind==b'VP8X' and len(body)>=10:
                if body[0]&2:raise AssetError('static')
                size=(int.from_bytes(body[4:7],'little')+1,int.from_bytes(body[7:10],'little')+1)
            if kind==b'VP8 ' and len(body)>=10 and body[3:6]==b'\x9d\x01\x2a':
                size=(struct.unpack('<H',body[6:8])[0]&16383,struct.unpack('<H',body[8:10])[0]&16383)
            if kind==b'VP8L' and len(body)>=5 and body[0]==47:
                bits=int.from_bytes(body[1:5],'little');size=((bits&16383)+1,((bits>>14)&16383)+1)
            pos+=8+length+(length%2)
        if size:return 'webp',size[0],size[1]
    raise AssetError('static')

def normalize(data):
    try:
        from PIL import Image, ImageOps
    except ImportError:
        ext,w,h=raster_info(data)
        if not(0<w<=SIDE and 0<h<=SIDE) or len(data)>MAX_CACHE:raise AssetError('static')
        return data,ext,w,h
    try:
        with Image.open(io.BytesIO(data)) as src:
            if src.width*src.height>16000000:raise AssetError('static')
            fmt=src.format;animated=getattr(src,'n_frames',1)>1
            src.seek(0)
            # Tiny static images only: small byte size must not hide huge dimensions.
            if len(data)<3072 and max(src.size)<=SIDE and not animated and fmt in ('PNG','JPEG','WEBP'):
                src.load();return data,{'PNG':'png','JPEG':'jpg','WEBP':'webp'}[fmt],src.width,src.height
            img=ImageOps.exif_transpose(src).convert('RGBA')
            img.thumbnail((SIDE,SIDE),getattr(Image,'Resampling',Image).LANCZOS)
            out=io.BytesIO();img.save(out,'WEBP',quality=72,method=4)
            result=out.getvalue()
            if len(result)>MAX_CACHE:raise AssetError('static')
            return result,'webp',img.width,img.height
    except AssetError:raise
    except Exception:raise AssetError('static')

def has_image_processor():
    try:
        from PIL import Image
        return True
    except ImportError:return False

class Resolver:
    def __init__(self,root,storage,key=None):
        self.root=Path(root);self.storage=Path(storage);self.private=private_directory(root)
        self.key=read_key(root) if key is None else key
        self.cache=self.storage/'ads'/'offline'

    def connect(self):
        self.private.mkdir(parents=True,exist_ok=True,mode=0o700)
        con=sqlite3.connect(str(self.private/'inscription-cache-v2.sqlite'),timeout=.25)
        con.execute('CREATE TABLE IF NOT EXISTS cache (ref TEXT PRIMARY KEY, metadata TEXT, asset TEXT, error TEXT, until REAL DEFAULT 0)')
        con.execute('CREATE TABLE IF NOT EXISTS budget (bucket TEXT PRIMARY KEY, n INTEGER NOT NULL)')
        con.commit()
        return con

    def api(self,con,path):
        if not self.key:raise AssetError('key')
        # Conservative local ceilings; Ordiscan's account-wide limit still applies.
        buckets=((time.strftime('month:%Y-%m',time.gmtime()),950),('minute:%d'%int(time.time()//60),90))
        for bucket,limit in buckets:
            row=con.execute('SELECT n FROM budget WHERE bucket=?',(bucket,)).fetchone()
            if row and row[0]>=limit:raise AssetError('quota')
        for bucket,_ in buckets:
            con.execute('INSERT OR IGNORE INTO budget VALUES (?,0)',(bucket,))
            con.execute('UPDATE budget SET n=n+1 WHERE bucket=?',(bucket,))
        con.execute('DELETE FROM budget WHERE bucket LIKE ? AND bucket!=?',('minute:%',buckets[1][0]))
        try:
            data=download('https://api.ordiscan.com/v1/'+path,2*1024*1024,key=self.key)
            return json.loads(data.decode('utf-8')).get('data')
        except urllib.error.HTTPError as e:
            raise AssetError('auth' if e.code in (401,403) else 'quota' if e.code in (402,429) else 'missing' if e.code==404 else 'upstream')
        except AssetError:raise
        except Exception:raise AssetError('upstream')

    def metadata(self,con,ref):
        if NUMBER.fullmatch(ref):
            number=int(ref)
            query=urllib.parse.urlencode({'sort':'inscription_number_asc','after':number-1,'before':number+1})
            rows=self.api(con,'inscriptions?'+query)
            exact=[r for r in (rows if isinstance(rows,list) else []) if isinstance(r,dict) and r.get('inscription_number')==number]
            if len(exact)!=1:raise AssetError('missing')
            meta=exact[0]
        else:meta=self.api(con,'inscription/'+ref)
        if not isinstance(meta,dict) or not ID.fullmatch(str(meta.get('inscription_id',''))):raise AssetError('missing')
        return {k:meta.get(k) for k in ('inscription_id','inscription_number','content_type','delegate_inscription_id','collection_slug')}

    def prepare(self,con,meta):
        original=meta;visited=set();current=meta
        for _ in range(4):
            require_image_metadata(current,allow_unknown=True)
            ins=current['inscription_id'];visited.add(ins)
            delegate=current.get('delegate_inscription_id')
            if delegate:
                if not ID.fullmatch(str(delegate)) or delegate in visited:raise AssetError('static')
                current=self.metadata(con,delegate);continue
            break
        else:raise AssetError('static')
        require_image_metadata(current)
        ins=current['inscription_id'];source='https://ordiscan.com/content/'+ins
        # Only trusted ordinal content hosts; never fetch arbitrary URLs in metadata.
        try:
            # Without a decoder, only attempt a genuinely tiny original; let
            # the thumbnail service download/resize larger originals instead.
            local=has_image_processor()
            result=normalize(download(source,MAX_SOURCE if local else 3071,timeout=10 if local else 6))
        except Exception:
            # Shared hosts without Pillow get a bounded first-frame static WebP.
            proxy='https://images.weserv.nl/?'+urllib.parse.urlencode({'url':'ordiscan.com/content/'+ins,'w':SIDE,'h':SIDE,'fit':'inside','output':'webp','q':72,'n':1})
            try:result=normalize(download(proxy,MAX_CACHE,timeout=12))
            except Exception:raise AssetError('static')
        return self.save(result,original)

    def save(self,result,meta):
        body,ext,w,h=result
        self.cache.mkdir(parents=True,exist_ok=True)
        name=hashlib.sha256(body).hexdigest()[:32]+'.'+ext
        path=self.cache/name
        if not path.exists():
            temporary=path.with_suffix(path.suffix+'.tmp');temporary.write_bytes(body);os.replace(str(temporary),str(path))
        return {'asset_url':'/storage/ads/offline/'+name,'inscription_id':meta['inscription_id'],'inscription_number':meta.get('inscription_number'),'bytes':len(body),'width':w,'height':h,'small_source':len(body)<3072}

    def existing(self,ref):
        try:assets=json.loads((self.storage/'ads/defaults/manifest-v1.json').read_text(encoding='utf-8')).get('assets',[])
        except (OSError,ValueError):return None
        for a in assets:
            matches=(NUMBER.fullmatch(ref) and str(a.get('number'))==str(int(ref))) or a.get('inscription_id')==ref
            url=a.get('asset_url','')
            if matches and url.startswith('/storage/ads/') and '..' not in url:
                require_image_metadata(a,allow_unknown=True)
                path=self.storage/url[len('/storage/'):]
                if not path.is_file():continue
                # Reuse existing curated thumbnails, but never promote an unchecked remote image.
                try:return self.save(normalize(path.read_bytes()),{'inscription_id':a['inscription_id'],'inscription_number':a.get('number')})
                except (OSError,AssetError,KeyError):continue
        return None

    def resolve(self,value):
        ref=str(value).strip().lower()
        if not(NUMBER.fullmatch(ref) or ID.fullmatch(ref)):raise AssetError('invalid')
        if NUMBER.fullmatch(ref):ref=str(int(ref))
        con=None;negative_hit=False
        try:
            con=self.connect();con.execute('BEGIN IMMEDIATE')
            row=con.execute('SELECT metadata,asset,error,until FROM cache WHERE ref=?',(ref,)).fetchone()
            meta=json.loads(row[0]) if row and row[0] else None
            if meta:
                try:require_image_metadata(meta,allow_unknown=True)
                except AssetError:
                    # Upgrade old cached HTML/3D failures immediately, before
                    # asset reuse and negative-cache checks. Do not slide TTL.
                    negative_hit=bool(row and row[2]=='type')
                    raise
            if row and row[1]:
                asset=json.loads(row[1]);url=asset['asset_url']
                if url.startswith('/storage/ads/') and '..' not in url and (self.storage/url[9:]).is_file():
                    con.commit();return asset
            if row and row[2] and row[3]>time.time():
                negative_hit=True;raise AssetError(row[2])
            asset=self.existing(ref)
            if asset is None:
                if meta is None:
                    meta=self.metadata(con,ref)
                    con.execute('INSERT OR REPLACE INTO cache (ref,metadata) VALUES (?,?)',(ref,json.dumps(meta)))
                asset=self.prepare(con,meta)
            con.execute('INSERT OR REPLACE INTO cache (ref,metadata,asset) VALUES (?,?,?)',(ref,json.dumps(meta),json.dumps(asset)))
            con.commit();return asset
        except AssetError as error:
            if con and not negative_hit:
                con.execute('INSERT INTO cache(ref) SELECT ? WHERE NOT EXISTS(SELECT 1 FROM cache WHERE ref=?)',(ref,ref))
                con.execute('UPDATE cache SET error=?,until=? WHERE ref=?',(error.code,time.time()+(300 if error.code=='missing' else 30),ref));con.commit()
            raise
        except sqlite3.OperationalError as error:
            logging.warning('Inscription cache unavailable: %s',str(error))
            raise AssetError('busy')
        except OSError:raise AssetError('upstream')
        finally:
            if con:con.close()
