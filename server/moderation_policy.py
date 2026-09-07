"""Shared political-focused display moderation; raw creative remains intact."""
import json
import re
import unicodedata
from pathlib import Path
PATH=Path(__file__).resolve().parent.parent/'resources/moderation/political-focus-v1.json'
POLICY=json.loads(PATH.read_text(encoding='utf-8'))
VERSION=POLICY['version']

def terms():
    return tuple(POLICY['terms'])

def normalize(value):
    text=unicodedata.normalize('NFKC',str(value))
    return ''.join(ch for ch in text if unicodedata.category(ch)!='Cf' and (ord(ch)>=32 or ch in '\n\t'))

def moderate(value):
    result=normalize(value);matches=[]
    for term in terms():
        pattern=re.escape(term)
        if all(ord(c)<128 for c in term):pattern=r'(?<![A-Za-z0-9])'+pattern+r'(?![A-Za-z0-9])'
        if re.search(pattern,result,re.I):
            matches.append(term);result=re.sub(pattern,lambda m:' '*len(m.group(0)),result,flags=re.I)
    return result,matches
