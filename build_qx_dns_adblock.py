#!/usr/bin/env python3
"""Build a Quantumult X DNS blocklist from hosts/plain-domain/AdGuard basic rules.
Mirrors the useful rule-compilation idea of esp32-c3-adblock, but outputs QX host-suffix rules.
"""
import argparse, ipaddress, re, sys, urllib.request
from pathlib import Path

DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists-legacy@latest/domains/light.txt',
]
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.I)

def valid_domain(s):
    s=s.strip().lower().rstrip('.')
    if s.startswith('*.'): s=s[2:]
    try: ipaddress.ip_address(s); return None
    except ValueError: pass
    return s if DOMAIN_RE.match(s) else None

def fetch(src):
    if src.startswith(('http://','https://')):
        req=urllib.request.Request(src, headers={'User-Agent':'qx-dns-adblock-builder/1.0'})
        with urllib.request.urlopen(req, timeout=45) as r:
            return r.read().decode('utf-8','ignore')
    return Path(src).read_text(encoding='utf-8', errors='ignore')

def parse(text):
    blocks=set(); allows=set(); skipped=0
    for raw in text.splitlines():
        s=raw.strip()
        if not s or s.startswith(('#','!','[',';')): continue
        allow=False
        if s.startswith('@@||'):
            allow=True; s=s[4:]
            s=s.split('^',1)[0].split('$',1)[0]
        elif s.startswith('||'):
            s=s[2:].split('^',1)[0].split('$',1)[0]
        elif s.startswith(('/','@@/')) or '##' in s or '#@#' in s:
            skipped+=1; continue
        else:
            parts=s.split()
            if len(parts)>=2 and parts[0] in ('0.0.0.0','127.0.0.1','::','::1'):
                s=parts[1]
            elif len(parts)>1:
                skipped+=1; continue
        d=valid_domain(s)
        if not d: skipped+=1; continue
        (allows if allow else blocks).add(d)
    return blocks, allows, skipped

def parent_reduce(domains):
    # Keep the shortest blocking suffix. If example.com is present, ads.example.com is redundant.
    kept=set()
    for d in sorted(domains, key=lambda x:(x.count('.'), len(x), x)):
        labels=d.split('.')
        redundant=False
        for i in range(1,len(labels)-1):
            if '.'.join(labels[i:]) in kept:
                redundant=True; break
        if not redundant: kept.add(d)
    return kept

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('output', nargs='?', default='qx-dns-adblock.list')
    ap.add_argument('sources', nargs='*')
    ap.add_argument('--allow', action='append', default=[], help='extra allowlist domain/file (repeatable)')
    ap.add_argument('--no-parent-reduce', action='store_true')
    args=ap.parse_args()
    sources=args.sources or DEFAULT_SOURCES
    blocks=set(); allows=set(); skipped=0
    for src in sources:
        print('fetch:',src,file=sys.stderr)
        b,a,s=parse(fetch(src)); blocks |= b; allows |= a; skipped += s
    for item in args.allow:
        p=Path(item)
        vals=p.read_text().splitlines() if p.exists() else [item]
        for v in vals:
            d=valid_domain(v)
            if d: allows.add(d)
    # Exact allow rules remove exact entries. We intentionally don't silently carve exceptions from a blocked parent.
    blocks -= allows
    before=len(blocks)
    if not args.no_parent_reduce: blocks=parent_reduce(blocks)
    out=Path(args.output)
    lines=[
        '# Quantumult X DNS AdBlock V2 generated list',
        '# Format: host-suffix,<domain>,reject',
        f'# Sources: {len(sources)} | parsed unique: {before} | compressed: {len(blocks)} | allow: {len(allows)} | skipped: {skipped}',
    ]
    lines += [f'host-suffix,{d},reject' for d in sorted(blocks)]
    out.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(f'wrote {out}: {len(blocks)} rules (from {before}), allow={len(allows)}, skipped={skipped}')
if __name__=='__main__': main()
